package se.swedenconnect.ca.cmc.api.impl;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.CertificationRequest;
import org.bouncycastle.asn1.cmc.LraPopWitness;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import se.swedenconnect.ca.cmc.api.CMCRequestParser;
import se.swedenconnect.ca.cmc.api.CMCResponseFactory;
import se.swedenconnect.ca.cmc.api.data.CMCControlObject;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.GenericExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.InheritExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.EncodedCertNameModel;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultCMCCaApi extends AbstractAdminCMCCaApi {

  public DefaultCMCCaApi(CAService caService,
    CMCRequestParser cmcRequestParser, CMCResponseFactory cmcResponseFactory) {
    super(caService, cmcRequestParser, cmcResponseFactory);
  }

  @Override CertificateModel getCertificateModel(CMCRequest cmcRequest) throws Exception {
    CertificationRequest certificationRequest = cmcRequest.getCertificationRequest();
    CertificateRequestMessage certificateRequestMessage = cmcRequest.getCertificateRequestMessage();

    if (certificationRequest != null) {
      return getCertificateModelFromPKCS10(certificationRequest);
    }

    CMCControlObject lraPWObject = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_lraPOPWitness, cmcRequest.getPkiData());
    LraPopWitness lraPopWitness = (LraPopWitness) lraPWObject.getValue();

    return getCertificateModelFromCRMF(certificateRequestMessage, lraPopWitness, cmcRequest.getCertReqBodyPartId());
  }

  private CertificateModel getCertificateModelFromCRMF(CertificateRequestMessage certificateRequestMessage, LraPopWitness lraPopWitness,
    BodyPartID certReqBodyPartId)  throws Exception{

    // Check POP
    if (lraPopWitness == null) {
      throw new IOException("Certificate request message format requests must hav LRA POP Witness set");
    }
    final List<Long> lraPopIdList = Arrays.asList(lraPopWitness.getBodyIds()).stream()
      .map(BodyPartID::getID)
      .collect(Collectors.toList());
    if (!lraPopIdList.contains(certReqBodyPartId.getID())){
      throw new IOException("No matching LRA POP Witness ID in CRMF request");
    }

    CertTemplate certTemplate = certificateRequestMessage.getCertTemplate();
    JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
    PublicKey publicKey = converter.getPublicKey(certTemplate.getPublicKey());
    Extensions extensions = certTemplate.getExtensions();
    ASN1ObjectIdentifier[] extensionOIDs = extensions.getExtensionOIDs();
    List<ExtensionModel> extensionModelList = new ArrayList<>();
    for (ASN1ObjectIdentifier extOid : extensionOIDs) {
      Extension extension = extensions.getExtension(extOid);
      extensionModelList.add(new GenericExtensionModel(
        extension.getExtnId(),
        extension.getParsedValue().toASN1Primitive(),
        extension.isCritical()
      ));
    }

    CertificateModel certificateModel = CertificateModel.builder()
      .publicKey(publicKey)
      .subject(new EncodedCertNameModel(certTemplate.getSubject()))
      .extensionModels(extensionModelList)
      .build();
    return certificateModel;
  }

  private CertificateModel getCertificateModelFromPKCS10(CertificationRequest certificationRequest) throws Exception {
    PKCS10CertificationRequest pkcs10Request = new PKCS10CertificationRequest(certificationRequest.getEncoded(ASN1Encoding.DER));
    PublicKey publicKey = validatePkcs10Signature(pkcs10Request);
    pkcs10Request.getSubject();

    Attribute[] p10ExtAttributes = pkcs10Request.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
    List<ExtensionModel> extensionModelList = new ArrayList<>();
    if (p10ExtAttributes != null && p10ExtAttributes.length > 0) {
      Attribute attribute = Attribute.getInstance(p10ExtAttributes[0]);
      ASN1Sequence extSequence = ASN1Sequence.getInstance(attribute.getAttrValues().getObjectAt(0));
      Iterator<ASN1Encodable> iterator = extSequence.iterator();
      while (iterator.hasNext()) {
        Extension extension = Extension.getInstance(iterator.next());
        extensionModelList.add(new GenericExtensionModel(
          extension.getExtnId(),
          extension.getParsedValue().toASN1Primitive(),
          extension.isCritical()
        ));
      }
    }

    CertificateModel certificateModel = CertificateModel.builder()
      .publicKey(publicKey)
      .subject(new EncodedCertNameModel(pkcs10Request.getSubject()))
      .extensionModels(extensionModelList)
      .build();
    return certificateModel;
  }

  private PublicKey validatePkcs10Signature(PKCS10CertificationRequest pkcs10Request)
    throws IOException, OperatorCreationException, PKCSException {
    JcaContentVerifierProviderBuilder builder = new JcaContentVerifierProviderBuilder().setProvider("BC");
    boolean signatureValid = pkcs10Request.isSignatureValid(builder.build(pkcs10Request.getSubjectPublicKeyInfo()));
    if (signatureValid) {
      return BouncyCastleProvider.getPublicKey(pkcs10Request.getSubjectPublicKeyInfo());
    }
    throw new IOException("Invalid PKCS10 signature");
  }

}