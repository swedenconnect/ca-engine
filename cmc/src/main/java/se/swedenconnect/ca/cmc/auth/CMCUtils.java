package se.swedenconnect.ca.cmc.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmc.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import se.swedenconnect.ca.cmc.api.CMCRequest;
import se.swedenconnect.ca.cmc.api.data.CMCControlObject;
import se.swedenconnect.ca.cmc.model.CMCRequestType;
import se.swedenconnect.ca.cmc.model.PEMType;
import se.swedenconnect.ca.cmc.model.admin.AdminRequestData;
import se.swedenconnect.ca.engine.ca.attribute.AttributeValueEncoder;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.engine.utils.CAUtils;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Utility functions for parsing and creating CMC messages
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMCUtils {

  public static final SecureRandom RNG = new SecureRandom();
  public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  public static CertificateRequestMessageBuilder getCRMFRequestMessageBuilder(BodyPartID requestId, CertificateModel certificateModel, AttributeValueEncoder attributeValueEncoder)
    throws IOException {
    CertificateRequestMessageBuilder crmfBuilder = new CertificateRequestMessageBuilder(new BigInteger(String.valueOf(requestId.getID())));
    crmfBuilder.setSubject(CAUtils.getX500Name(certificateModel.getSubject(), attributeValueEncoder));

    SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
      ASN1Sequence.getInstance(certificateModel.getPublicKey().getEncoded()));
    crmfBuilder.setPublicKey(subjectPublicKeyInfo);

    List<ExtensionModel> extensionModels = certificateModel.getExtensionModels();
    for (ExtensionModel extensionModel: extensionModels){
      List<Extension> extensions = extensionModel.getExtensions();
      for (Extension extension: extensions){
        crmfBuilder.addExtension(extension.getExtnId(), extension.isCritical(), extension.getExtnValue());
      }
    }
    return crmfBuilder;
  }

  public static CertificationRequest getCertificationRequest(CertificateModel certificateModel, ContentSigner signer, AttributeValueEncoder attributeValueEncoder)
    throws IOException {

    X500Name subjectX500Name = CAUtils.getX500Name(certificateModel.getSubject(), attributeValueEncoder);
    SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
      ASN1Sequence.getInstance(certificateModel.getPublicKey().getEncoded()));

    PKCS10CertificationRequestBuilder p10ReqBuilder = new PKCS10CertificationRequestBuilder(subjectX500Name, subjectPublicKeyInfo);
    ExtensionsGenerator extGen = new ExtensionsGenerator();
    List<ExtensionModel> extensionModels = certificateModel.getExtensionModels();
    for (ExtensionModel extensionModel: extensionModels){
      List<Extension> extensions = extensionModel.getExtensions();
      for (Extension extension: extensions){
        extGen.addExtension(extension);
      }
    }
    p10ReqBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
    PKCS10CertificationRequest pkcs10 = p10ReqBuilder.build(signer);
    return CertificationRequest.getInstance(pkcs10.toASN1Structure().toASN1Primitive());
  }

  public static byte[] signEncapsulatedCMSContent(ASN1ObjectIdentifier contentType, ASN1Encodable content, List<X509Certificate> signerCertChain, ContentSigner signer) throws IOException {
    try {
      final Store<?> certs = new JcaCertStore(signerCertChain);
      final CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
      final org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(
        ASN1Primitive.fromByteArray(signerCertChain.get(0).getEncoded()));
      //final ContentSigner signer = new JcaContentSignerBuilder(CAAlgorithmRegistry.getSigAlgoName(algorithm)).build(signKey);
      final JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build());
      gen.addSignerInfoGenerator(builder.build(signer, new X509CertificateHolder(cert)));
      gen.addCertificates(certs);
      //final CMSTypedData encapsulatedContent = new PKCS7ProcessableObject(contentType, content);
      final CMSProcessableByteArray encapsulatedContent = new CMSProcessableByteArray(contentType, content.toASN1Primitive().getEncoded(ASN1Encoding.DER));
      final CMSSignedData resultSignedData = gen.generate(encapsulatedContent, true);
      return resultSignedData.toASN1Structure().getEncoded(ASN1Encoding.DL);
    }
    catch (GeneralSecurityException | CMSException | OperatorCreationException e) {
      final String msg = String.format("Failed to sign content - %s", e.getMessage());
      log.error("{}", msg, e);
      throw new IOException(msg, e);
    }
  }

  public static String getPemFormatedObject(byte[] data, PEMType pemType) throws IOException {
    PemObject pemObject = new PemObject(pemType.getHeader(), data);
    StringWriter strWr = new StringWriter();
    PemWriter pemWriter = new PemWriter(strWr);
    pemWriter.writeObject(pemObject);
    pemWriter.close();
    strWr.close();
    PEMParser pp;
    return strWr.toString();
  }

  public static CMCControlObject getCMCControlObject(ASN1ObjectIdentifier controlOid, PKIData pkiData) throws IOException {
    return getCMCControlObject(controlOid, pkiData, null);
  }
  public static CMCControlObject getCMCControlObject(ASN1ObjectIdentifier controlOid, PKIData pkiData, CMCRequestType cmcRequestType)
    throws IOException {
    CMCControlObject.CMCControlObjectBuilder resultBuilder = CMCControlObject.builder().type(controlOid);
    TaggedAttribute[] controlSequence = pkiData.getControlSequence();
    for (TaggedAttribute controlAttr : controlSequence){
      ASN1ObjectIdentifier attrType = controlAttr.getAttrType();
      if (attrType != null && attrType.equals(controlOid)){
        resultBuilder
          .bodyPartID(controlAttr.getBodyPartID())
          .value(getRequestControlValue(controlOid, controlAttr.getAttrValues(), cmcRequestType));
      }
    }
    return resultBuilder.build();
  }

  private static Object getRequestControlValue(ASN1ObjectIdentifier controlOid, ASN1Set controlAttrVals, CMCRequestType cmcRequestType)
    throws IOException {
    Object controlValue = getControlValue(controlOid, controlAttrVals);
    if (CMCObjectIdentifiers.id_cmc_regInfo.equals(controlOid)){
      byte[] regInfoBytes = (byte[]) controlValue;
      if (CMCRequestType.admin.equals(cmcRequestType)){
        return OBJECT_MAPPER.readValue(regInfoBytes, AdminRequestData.class);
      }
    }
    return controlValue;
  }


  private static Object getControlValue(ASN1ObjectIdentifier controlOid, ASN1Set controlAttrVals)
    throws IOException {

    try {
      if (controlAttrVals.size()==0){
        log.debug("No values - Returning null");
        return null;
      }
      ASN1Encodable firstObject = controlAttrVals.getObjectAt(0);
      if (firstObject == null){
        log.debug("No control value - Returning null");
        return null;
      }

      if (CMCObjectIdentifiers.id_cmc_regInfo.equals(controlOid)
        || CMCObjectIdentifiers.id_cmc_responseInfo.equals(controlOid)
        || CMCObjectIdentifiers.id_cmc_senderNonce.equals(controlOid)
        || CMCObjectIdentifiers.id_cmc_recipientNonce.equals(controlOid)
      ){
        return ASN1OctetString.getInstance(firstObject).getOctets();
      }
      if (CMCObjectIdentifiers.id_cmc_getCert.equals(controlOid)){
        return GetCert.getInstance(firstObject);
      }
      if (CMCObjectIdentifiers.id_cmc_lraPOPWitness.equals(controlOid)){
        return LraPopWitness.getInstance(firstObject);
      }
      if (CMCObjectIdentifiers.id_cmc_revokeRequest.equals(controlOid)){
        return RevokeRequest.getInstance(firstObject);
      }
      if (CMCObjectIdentifiers.id_cmc_statusInfoV2.equals(controlOid)){
        return CMCStatusInfoV2.getInstance(firstObject);
      }
    } catch (Exception ex){
      throw new IOException("Error extracting CMC control value", ex);
    }
    log.debug("Unsupported CMC control message {} - returning null", controlOid);
    return null;
  }
}
