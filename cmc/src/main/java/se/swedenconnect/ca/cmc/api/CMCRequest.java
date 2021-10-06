package se.swedenconnect.ca.cmc.api;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmc.*;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.auth.CMCValidationResult;
import se.swedenconnect.ca.cmc.auth.CMCValidator;
import se.swedenconnect.ca.cmc.model.request.CMCRequestModel;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.cmc.model.request.admin.AdminRequestData;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * This class implements a CMC request to a CA instance
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMCRequest {

  private final static SecureRandom RNG = new SecureRandom();

  @Getter private byte[] cmcRequestBytes;
  @Getter private byte[] nonce;
  @Getter CMCRequestType cmcRequestType;
  @Getter CertificationRequest certificationRequest;
  @Getter CertificateRequestMessage certificateRequestMessage;
  @Getter BodyPartID certReqBodyPartId;
  @Getter PKIData pkiData;

  /**
   * Constructor from CMC Request bytes
   * @param cmcRequestBytes the bytes of a CMC request
   * @param validator validator for validating the signature of the CMC request and authorization to sign request
   * @throws IOException on error parsing the CMC request
   */
  public CMCRequest(byte[] cmcRequestBytes, CMCValidator validator) throws IOException {
    this.cmcRequestBytes = cmcRequestBytes;
    parseRequest(validator);
  }

  /**
   * Constructor from CMC Request model data
   * @param cmcRequestModel CMC Request model data
   * @throws IOException on error building a CMC request from the model data
   */
  public CMCRequest(CMCRequestModel cmcRequestModel) throws IOException {
    cmcRequestType = cmcRequestModel.getCmcRequestType();
    try {
      switch (cmcRequestType) {
      case issueCert:
        pkiData = createCertRequest((CMCCertificateRequestModel) cmcRequestModel);
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
      if (pkiData != null) {
        this.cmcRequestBytes = CMCUtils.signEncapsulatedCMSContent(
          CMCObjectIdentifiers.id_cct_PKIData,
          pkiData, cmcRequestModel.getCmcSignerCerts(), cmcRequestModel.getCmcSigner());
      }
    }
    catch (Exception ex) {
      throw new IOException("Error generating CMC request", ex);
    }
  }

  private void parseRequest(CMCValidator validator) throws IOException {
    CMCValidationResult cmcValidationResult = validator.validateCMC(cmcRequestBytes);
    if (!CMCObjectIdentifiers.id_cct_PKIData.equals(cmcValidationResult.getContentType())) {
      throw new IOException("Illegal CMS content type for CMC request");
    }
    try {
      CMSSignedData signedData = cmcValidationResult.getSignedData();
      pkiData = PKIData.getInstance(new ASN1InputStream((byte[]) cmcValidationResult.getSignedData().getSignedContent().getContent()).readObject());
      // Get certification request
      TaggedRequest[] reqSequence = pkiData.getReqSequence();
      if (reqSequence.length > 0) {
        TaggedRequest taggedRequest = reqSequence[0];
        ASN1Encodable taggedRequestValue = taggedRequest.getValue();
        boolean popCheckOK = false;
        if (taggedRequestValue instanceof TaggedCertificationRequest) {
          TaggedCertificationRequest taggedCertReq = (TaggedCertificationRequest) taggedRequestValue;
          ASN1Sequence taggedCertReqSeq = ASN1Sequence.getInstance(taggedCertReq.toASN1Primitive());
          certReqBodyPartId = BodyPartID.getInstance(taggedCertReqSeq.getObjectAt(0));
          certificationRequest = CertificationRequest.getInstance(taggedCertReqSeq.getObjectAt(1));
          popCheckOK = true;
        }
        if (taggedRequestValue instanceof CertReqMsg) {
          certificateRequestMessage = new CertificateRequestMessage((CertReqMsg) taggedRequestValue);
          ASN1Integer certReqId = ((CertReqMsg) taggedRequestValue).getCertReq().getCertReqId();
          certReqBodyPartId = new BodyPartID(certReqId.longValueExact());
          popCheckOK = isLraWitnessMatch();
        }
        if (!popCheckOK){
          throw new IllegalArgumentException("POP check failed");
        }
      }
      cmcRequestType = getRequestType();
      nonce = (byte[]) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_senderNonce, pkiData).getValue();
    }
    catch (Exception ex) {
      log.debug("Error parsing PKI Data from CMC request", ex.toString());
      throw new IOException("Error parsing PKI Data from CMC request", ex);
    }
  }

  private boolean isLraWitnessMatch() throws IOException {
    LraPopWitness lraPopWitness = (LraPopWitness) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_lraPOPWitness, pkiData).getValue();
    if (lraPopWitness != null) {
      BodyPartID[] bodyIds = lraPopWitness.getBodyIds();
      return Arrays.stream(bodyIds)
        .anyMatch(bodyPartID -> bodyPartID.equals(certReqBodyPartId));
    }
    return false;
  }

  private CMCRequestType getRequestType() throws IOException {
    if (certificationRequest != null || certificateRequestMessage != null){
      return CMCRequestType.issueCert;
    }
    if (CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_revokeRequest, pkiData).getValue() != null){
      return CMCRequestType.revoke;
    }
    if (CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_getCert, pkiData).getValue() != null){
      return CMCRequestType.getCert;
    }
    Object regInfoObj = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_regInfo, pkiData, CMCRequestType.admin).getValue();
    if (regInfoObj != null && regInfoObj instanceof AdminRequestData){
      return CMCRequestType.admin;
    }
    throw new IOException("Illegal request type");
  }



  private PKIData createGetCertRequest(CMCGetCertRequestModel cmcRequestModel) {
    return new PKIData(getGetCertsControlSequence(cmcRequestModel), new TaggedRequest[] {}, new TaggedContentInfo[] {}, new OtherMsg[] {});
  }

  private TaggedAttribute[] getGetCertsControlSequence(CMCGetCertRequestModel cmcRequestModel) {
    List<TaggedAttribute> taggedAttributeList = new ArrayList<>();
    addNonceControl(taggedAttributeList, cmcRequestModel);
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
    addNonceControl(taggedAttributeList, cmcRequestModel);
    addRegistrationInfoControl(taggedAttributeList, cmcRequestModel);
    return taggedAttributeList.toArray(new TaggedAttribute[taggedAttributeList.size()]);
  }

  public PKIData createCertRequest(CMCCertificateRequestModel cmcRequestModel)
    throws NoSuchAlgorithmException, OperatorCreationException, IOException, CRMFException {

    TaggedRequest taggedCertificateRequest;
    certReqBodyPartId = getBodyPartId();
    TaggedAttribute[] controlSequence = getCertRequestControlSequence(cmcRequestModel);
    PrivateKey certReqPrivate = cmcRequestModel.getCertReqPrivate();
    if (certReqPrivate != null) {
      ContentSigner p10Signer = new JcaContentSignerBuilder(CAAlgorithmRegistry.getSigAlgoName(cmcRequestModel.getP10Algorithm()))
        .build(certReqPrivate);
      certificationRequest = CMCUtils.getCertificationRequest(cmcRequestModel.getCertificateModel(), p10Signer,
        new AttributeValueEncoder());
      taggedCertificateRequest = new TaggedRequest(new TaggedCertificationRequest(certReqBodyPartId, certificationRequest));
    }
    else {
      CertificateRequestMessageBuilder crmfBuilder = CMCUtils.getCRMFRequestMessageBuilder(certReqBodyPartId,
        cmcRequestModel.getCertificateModel(), new AttributeValueEncoder());
      extendCertTemplate(crmfBuilder, cmcRequestModel);
      certificateRequestMessage = crmfBuilder.build();
      taggedCertificateRequest = new TaggedRequest(certificateRequestMessage.toASN1Structure());
    }

    return new PKIData(controlSequence, new TaggedRequest[] { taggedCertificateRequest }, new TaggedContentInfo[] {}, new OtherMsg[] {});
  }

  protected void extendCertTemplate(CertificateRequestMessageBuilder crmfBuilder, CMCCertificateRequestModel cmcRequestModel) {
    // Extend crmf cert template based on cmcRequestModel
  }

  private BodyPartID getBodyPartId() {
    return getBodyPartId(new BigInteger(31, RNG).add(BigInteger.ONE));
  }

  private BodyPartID getBodyPartId(BigInteger bodyPartId) {

    long id = Long.valueOf(bodyPartId.toString(10));
    return new BodyPartID(id);
  }

  private TaggedAttribute[] getCertRevocationControlSequence(CMCRevokeRequestModel cmcRequestModel)
    throws CertificateEncodingException, IOException {
    List<TaggedAttribute> taggedAttributeList = new ArrayList<>();
    addNonceControl(taggedAttributeList, cmcRequestModel);
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

  private TaggedAttribute[] getCertRequestControlSequence(CMCCertificateRequestModel cmcRequestModel) {
    List<TaggedAttribute> taggedAttributeList = new ArrayList<>();
    addNonceControl(taggedAttributeList, cmcRequestModel);
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

  private void addNonceControl(List<TaggedAttribute> taggedAttributeList, CMCRequestModel cmcRequestModel) {
    nonce = cmcRequestModel.getNonce();
    if (nonce != null) {
      taggedAttributeList.add(getControl(CMCObjectIdentifiers.id_cmc_senderNonce, new DEROctetString(nonce)));
    }
  }

  private TaggedAttribute getControl(ASN1ObjectIdentifier oid, ASN1Encodable... values) {
    return getControl(oid, null, values);
  }

  private TaggedAttribute getControl(ASN1ObjectIdentifier oid, BodyPartID id, ASN1Encodable... values) {
    if (id == null) {
      id = getBodyPartId();
    }
    ASN1Set valueSet = getSet(values);
    return new TaggedAttribute(id, oid, valueSet);
  }

  private ASN1Set getSet(ASN1Encodable... content) {
    ASN1EncodableVector valueSet = new ASN1EncodableVector();
    for (ASN1Encodable data : content) {
      valueSet.add(data);
    }
    return new DERSet(valueSet);
  }

}
