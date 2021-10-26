package se.swedenconnect.ca.cmc.api;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmc.*;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cms.CMSSignedData;
import se.swedenconnect.ca.cmc.api.data.CMCControlObjectID;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.auth.CMCReplayChecker;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.auth.CMCValidationResult;
import se.swedenconnect.ca.cmc.auth.CMCValidator;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;

/**
 * Parser for CMC Request data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMCRequestParser {

  private final CMCValidator validator;
  private final CMCReplayChecker replayChecker;

  /**
   * Constructor for the CMC data parser
   * @param validator the validator used to validate the signature and authorization of the CMC signer to provide a CMC request
   */
  public CMCRequestParser(CMCValidator validator, CMCReplayChecker cmcReplayChecker) {
    this.validator = validator;
    this.replayChecker = cmcReplayChecker;
  }

  public CMCRequest parseCMCrequest(byte[] cmcRequestBytes) throws IOException {
    CMCRequest cmcRequest = new CMCRequest();
    cmcRequest.setCmcRequestBytes(cmcRequestBytes);

    CMCValidationResult cmcValidationResult = validator.validateCMC(cmcRequestBytes);
    if (!CMCObjectIdentifiers.id_cct_PKIData.equals(cmcValidationResult.getContentType())) {
      throw new IOException("Illegal CMS content type for CMC request");
    }
    try {
      CMSSignedData signedData = cmcValidationResult.getSignedData();
      PKIData pkiData = PKIData.getInstance(new ASN1InputStream((byte[]) signedData.getSignedContent().getContent()).readObject());
      replayChecker.validate(pkiData);
      cmcRequest.setPkiData(pkiData);
      // Get certification request
      TaggedRequest[] reqSequence = pkiData.getReqSequence();
      if (reqSequence.length > 0) {
        TaggedRequest taggedRequest = reqSequence[0];
        ASN1Encodable taggedRequestValue = taggedRequest.getValue();
        boolean popCheckOK = false;
        if (taggedRequestValue instanceof TaggedCertificationRequest) {
          TaggedCertificationRequest taggedCertReq = (TaggedCertificationRequest) taggedRequestValue;
          ASN1Sequence taggedCertReqSeq = ASN1Sequence.getInstance(taggedCertReq.toASN1Primitive());
          BodyPartID certReqBodyPartId = BodyPartID.getInstance(taggedCertReqSeq.getObjectAt(0));
          cmcRequest.setCertReqBodyPartId(certReqBodyPartId);
          CertificationRequest certificationRequest = CertificationRequest.getInstance(taggedCertReqSeq.getObjectAt(1));
          cmcRequest.setCertificationRequest(certificationRequest);
          popCheckOK = true;
        }
        if (taggedRequestValue instanceof CertReqMsg) {
          CertificateRequestMessage certificateRequestMessage = new CertificateRequestMessage((CertReqMsg) taggedRequestValue);
          cmcRequest.setCertificateRequestMessage(certificateRequestMessage);
          ASN1Integer certReqId = ((CertReqMsg) taggedRequestValue).getCertReq().getCertReqId();
          BodyPartID certReqBodyPartId = new BodyPartID(certReqId.longValueExact());
          cmcRequest.setCertReqBodyPartId(certReqBodyPartId);
          popCheckOK = isLraWitnessMatch(pkiData, certReqBodyPartId);
        }
        if (!popCheckOK){
          throw new IllegalArgumentException("POP check failed");
        }
      }
      setRequestType(cmcRequest);
      byte[] nonce = (byte[]) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_senderNonce, pkiData).getValue();
      cmcRequest.setNonce(nonce);
      cmcRequest.setMessageTime((Date) CMCUtils.getCMCControlObject(CMCControlObjectID.messageTime.getOid(), pkiData).getValue());

    }
    catch (Exception ex) {
      if (ex instanceof IOException){
        throw (IOException) ex;
      }
      log.debug("Error parsing PKI Data from CMC request", ex.toString());
      throw new IOException("Error parsing PKI Data from CMC request", ex);
    }
    return cmcRequest;
  }

  private boolean isLraWitnessMatch(PKIData pkiData, BodyPartID certReqBodyPartId) throws IOException {
    LraPopWitness lraPopWitness = (LraPopWitness) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_lraPOPWitness, pkiData).getValue();
    if (lraPopWitness != null) {
      BodyPartID[] bodyIds = lraPopWitness.getBodyIds();
      return Arrays.stream(bodyIds)
        .anyMatch(bodyPartID -> bodyPartID.equals(certReqBodyPartId));
    }
    return false;
  }

  private void setRequestType(CMCRequest cmcRequest) throws IOException {
    if (cmcRequest.getCertificationRequest() != null || cmcRequest.getCertificateRequestMessage() != null){
      cmcRequest.setCmcRequestType(CMCRequestType.issueCert);
      return;
    }
    if (CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_revokeRequest, cmcRequest.getPkiData()).getValue() != null){
      cmcRequest.setCmcRequestType(CMCRequestType.revoke);
      return;
    }
    if (CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_getCert, cmcRequest.getPkiData()).getValue() != null){
      cmcRequest.setCmcRequestType(CMCRequestType.getCert);
      return;
    }
    Object regInfoObj = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_regInfo, cmcRequest.getPkiData()).getValue();
    if (regInfoObj != null && regInfoObj instanceof AdminCMCData){
      cmcRequest.setCmcRequestType(CMCRequestType.admin);
      return;
    }
    throw new IOException("Illegal request type");
  }

}
