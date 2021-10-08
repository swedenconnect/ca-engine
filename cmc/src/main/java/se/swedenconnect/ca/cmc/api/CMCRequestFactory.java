package se.swedenconnect.ca.cmc.api;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmc.*;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.request.CMCRequestModel;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.cmc.model.request.impl.CMCAdminRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCCertificateRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCGetCertRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCRevokeRequestModel;
import se.swedenconnect.ca.engine.ca.attribute.AttributeValueEncoder;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCRequestFactory {

  private final static SecureRandom RNG = new SecureRandom();
  private final List<X509Certificate> signerCertChain;
  private final ContentSigner signer;

  public CMCRequestFactory(List<X509Certificate> signerCertChain, ContentSigner signer) {
    this.signerCertChain = signerCertChain;
    this.signer = signer;
  }

  public CMCRequest getCMCRequest(CMCRequestModel cmcRequestModel) throws IOException {
    CMCRequest.CMCRequestBuilder requestBuilder = CMCRequest.builder();
    CMCRequestType cmcRequestType = cmcRequestModel.getCmcRequestType();
    requestBuilder
      .cmcRequestType(cmcRequestType)
      .nonce(cmcRequestModel.getNonce());
    PKIData pkiData = null;
    try {
      switch (cmcRequestType) {
      case issueCert:
        pkiData = createCertRequest((CMCCertificateRequestModel) cmcRequestModel);
        addCertRequestData(pkiData, requestBuilder);
        break;
      case revoke:
        pkiData = new PKIData(getCertRevocationControlSequence((CMCRevokeRequestModel) cmcRequestModel),
          new TaggedRequest[] {}, new TaggedContentInfo[] {}, new OtherMsg[] {});
        break;
      case admin:
        pkiData = createAdminRequest((CMCAdminRequestModel) cmcRequestModel);
        break;
      case getCert:
        pkiData = createGetCertRequest((CMCGetCertRequestModel) cmcRequestModel);
        break;
      }
      requestBuilder
        .pkiData(pkiData)
        .cmcRequestBytes(CMCUtils.signEncapsulatedCMSContent(
          CMCObjectIdentifiers.id_cct_PKIData,
          pkiData, signerCertChain, signer));
    }
    catch (Exception ex) {
      throw new IOException("Error generating CMC request", ex);
    }
    return requestBuilder.build();
  }

  private PKIData createGetCertRequest(CMCGetCertRequestModel cmcRequestModel) {
    return new PKIData(getGetCertsControlSequence(cmcRequestModel), new TaggedRequest[] {}, new TaggedContentInfo[] {}, new OtherMsg[] {});
  }

  private TaggedAttribute[] getGetCertsControlSequence(CMCGetCertRequestModel cmcRequestModel) {
    List<TaggedAttribute> taggedAttributeList = new ArrayList<>();
    addNonceControl(taggedAttributeList, cmcRequestModel.getNonce());
    addRegistrationInfoControl(taggedAttributeList, cmcRequestModel);
    GeneralName gn = new GeneralName(cmcRequestModel.getIssuerName());
    GetCert getCert = new GetCert(gn, cmcRequestModel.getSerialNumber());
    taggedAttributeList.add(getControl(CMCObjectIdentifiers.id_cmc_getCert, getCert));
    return taggedAttributeList.toArray(new TaggedAttribute[taggedAttributeList.size()]);
  }

  private PKIData createAdminRequest(CMCAdminRequestModel cmcRequestModel) throws IOException {
    return new PKIData(getAdminControlSequence(cmcRequestModel), new TaggedRequest[] {}, new TaggedContentInfo[] {}, new OtherMsg[] {});
  }

  private TaggedAttribute[] getAdminControlSequence(CMCAdminRequestModel cmcRequestModel) throws IOException {
    List<TaggedAttribute> taggedAttributeList = new ArrayList<>();
    addNonceControl(taggedAttributeList, cmcRequestModel.getNonce());
    addRegistrationInfoControl(taggedAttributeList, cmcRequestModel);
    return taggedAttributeList.toArray(new TaggedAttribute[taggedAttributeList.size()]);
  }

  public PKIData createCertRequest(CMCCertificateRequestModel cmcRequestModel)
    throws NoSuchAlgorithmException, OperatorCreationException, IOException, CRMFException {

    TaggedRequest taggedCertificateRequest;
    BodyPartID certReqBodyPartId = getBodyPartId();
    TaggedAttribute[] controlSequence = getCertRequestControlSequence(cmcRequestModel, cmcRequestModel.getNonce(), certReqBodyPartId);
    PrivateKey certReqPrivate = cmcRequestModel.getCertReqPrivate();
    if (certReqPrivate != null) {
      ContentSigner p10Signer = new JcaContentSignerBuilder(CAAlgorithmRegistry.getSigAlgoName(cmcRequestModel.getP10Algorithm()))
        .build(certReqPrivate);
      CertificationRequest certificationRequest = CMCUtils.getCertificationRequest(cmcRequestModel.getCertificateModel(), p10Signer,
        new AttributeValueEncoder());
      taggedCertificateRequest = new TaggedRequest(new TaggedCertificationRequest(certReqBodyPartId, certificationRequest));
    }
    else {
      CertificateRequestMessageBuilder crmfBuilder = CMCUtils.getCRMFRequestMessageBuilder(certReqBodyPartId,
        cmcRequestModel.getCertificateModel(), new AttributeValueEncoder());
      extendCertTemplate(crmfBuilder, cmcRequestModel);
      CertificateRequestMessage certificateRequestMessage = crmfBuilder.build();
      taggedCertificateRequest = new TaggedRequest(certificateRequestMessage.toASN1Structure());
    }

    return new PKIData(controlSequence, new TaggedRequest[] { taggedCertificateRequest }, new TaggedContentInfo[] {}, new OtherMsg[] {});
  }

  protected void extendCertTemplate(CertificateRequestMessageBuilder crmfBuilder, CMCCertificateRequestModel cmcRequestModel) {
    // Extend crmf cert template based on cmcRequestModel
  }

  public static BodyPartID getBodyPartId() {
    return getBodyPartId(new BigInteger(31, RNG).add(BigInteger.ONE));
  }

  public static BodyPartID getBodyPartId(BigInteger bodyPartId) {

    long id = Long.valueOf(bodyPartId.toString(10));
    return new BodyPartID(id);
  }

  private TaggedAttribute[] getCertRevocationControlSequence(CMCRevokeRequestModel cmcRequestModel)
    throws CertificateEncodingException, IOException {
    CMCRequest cmcRequest = new CMCRequest();
    List<TaggedAttribute> taggedAttributeList = new ArrayList<>();
    addNonceControl(taggedAttributeList, cmcRequestModel.getNonce());
    addRegistrationInfoControl(taggedAttributeList, cmcRequestModel);
    RevokeRequest revokeRequest = new RevokeRequest(
      cmcRequestModel.getIssuerName(),
      new ASN1Integer(cmcRequestModel.getSerialNumber()),
      CRLReason.lookup(cmcRequestModel.getReason()),
      new ASN1GeneralizedTime(cmcRequestModel.getRevocationDate()), null, null
    );
    taggedAttributeList.add(getControl(CMCObjectIdentifiers.id_cmc_revokeRequest, revokeRequest));
    return taggedAttributeList.toArray(new TaggedAttribute[taggedAttributeList.size()]);
  }

  private TaggedAttribute[] getCertRequestControlSequence(CMCCertificateRequestModel cmcRequestModel, byte[] nonce,
    BodyPartID certReqBodyPartId) {
    List<TaggedAttribute> taggedAttributeList = new ArrayList<>();
    addNonceControl(taggedAttributeList, nonce);
    addRegistrationInfoControl(taggedAttributeList, cmcRequestModel);
    if (cmcRequestModel.isLraPopWitness()) {
      ASN1EncodableVector lraPopWitSeq = new ASN1EncodableVector();
      lraPopWitSeq.add(getBodyPartId());
      lraPopWitSeq.add(new DERSequence(certReqBodyPartId));
      taggedAttributeList.add(getControl(CMCObjectIdentifiers.id_cmc_lraPOPWitness, new DERSequence(lraPopWitSeq)));
    }
    return taggedAttributeList.toArray(new TaggedAttribute[taggedAttributeList.size()]);
  }

  private void addRegistrationInfoControl(List<TaggedAttribute> taggedAttributeList, CMCRequestModel cmcRequestModel) {
    byte[] registrationInfo = cmcRequestModel.getRegistrationInfo();
    if (registrationInfo != null) {
      taggedAttributeList.add(getControl(CMCObjectIdentifiers.id_cmc_regInfo, new DEROctetString(registrationInfo)));
    }
  }

  public static void addNonceControl(List<TaggedAttribute> taggedAttributeList, byte[] nonce) {
    if (nonce != null) {
      taggedAttributeList.add(getControl(CMCObjectIdentifiers.id_cmc_senderNonce, new DEROctetString(nonce)));
    }
  }

  public static TaggedAttribute getControl(ASN1ObjectIdentifier oid, ASN1Encodable... values) {
    return getControl(oid, null, values);
  }

  public static TaggedAttribute getControl(ASN1ObjectIdentifier oid, BodyPartID id, ASN1Encodable... values) {
    if (id == null) {
      id = getBodyPartId();
    }
    ASN1Set valueSet = getSet(values);
    return new TaggedAttribute(id, oid, valueSet);
  }

  public static ASN1Set getSet(ASN1Encodable... content) {
    ASN1EncodableVector valueSet = new ASN1EncodableVector();
    for (ASN1Encodable data : content) {
      valueSet.add(data);
    }
    return new DERSet(valueSet);
  }

  private void addCertRequestData(PKIData pkiData, CMCRequest.CMCRequestBuilder cmcRequestBuilder) {
    if (pkiData == null || pkiData.getReqSequence() == null) {
      return;
    }
    TaggedRequest[] reqSequence = pkiData.getReqSequence();
    for (TaggedRequest taggedRequest : reqSequence) {
      ASN1Encodable taggedRequestValue = taggedRequest.getValue();
      if (taggedRequestValue instanceof TaggedCertificationRequest) {
        TaggedCertificationRequest taggedCertReq = (TaggedCertificationRequest) taggedRequestValue;
        ASN1Sequence taggedCertReqSeq = ASN1Sequence.getInstance(taggedCertReq.toASN1Primitive());
        BodyPartID certReqBodyPartId = BodyPartID.getInstance(taggedCertReqSeq.getObjectAt(0));
        CertificationRequest certificationRequest = CertificationRequest.getInstance(taggedCertReqSeq.getObjectAt(1));
        cmcRequestBuilder
          .certificationRequest(certificationRequest)
          .certReqBodyPartId(certReqBodyPartId);
        return;
      }
      if (taggedRequestValue instanceof CertReqMsg) {
        CertificateRequestMessage certificateRequestMessage = new CertificateRequestMessage((CertReqMsg) taggedRequestValue);
        ASN1Integer certReqId = ((CertReqMsg) taggedRequestValue).getCertReq().getCertReqId();
        BodyPartID certReqBodyPartId = new BodyPartID(certReqId.longValueExact());
        cmcRequestBuilder
          .certificateRequestMessage(certificateRequestMessage)
          .certReqBodyPartId(certReqBodyPartId);
        return;
      }
    }
  }

}
