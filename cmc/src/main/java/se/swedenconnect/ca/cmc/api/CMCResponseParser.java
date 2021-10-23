package se.swedenconnect.ca.cmc.api;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmc.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import se.swedenconnect.ca.cmc.api.data.*;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.auth.CMCValidationResult;
import se.swedenconnect.ca.cmc.auth.CMCValidator;
import se.swedenconnect.ca.engine.utils.CAUtils;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMCResponseParser {

  private final CMCValidator validator;
  private final PublicKey caPublicKey;

  public CMCResponseParser(CMCValidator validator, PublicKey caPublicKey) {
    this.validator = validator;
    this.caPublicKey = caPublicKey;
  }

  public CMCResponse parseCMCresponse(byte[] cmcResponseBytes) throws IOException {
    return parseCMCresponse(cmcResponseBytes, false);
  }
  public CMCResponse parseCMCresponse(byte[] cmcResponseBytes, boolean expectCertsOnSuccess) throws IOException {
    CMCResponse.CMCResponseBuilder responseBuilder = CMCResponse.builder();
    responseBuilder.cmcResponseBytes(cmcResponseBytes);

    CMCValidationResult cmcValidationResult = validator.validateCMC(cmcResponseBytes);
    if (!CMCObjectIdentifiers.id_cct_PKIResponse.equals(cmcValidationResult.getContentType())) {
      throw new IOException("Illegal CMS content type for CMC request");
    }

    try {
      CMSSignedData signedData = cmcValidationResult.getSignedData();
      PKIResponse pkiResponse = PKIResponse.getInstance(new ASN1InputStream((byte[]) signedData.getSignedContent().getContent()).readObject());
      responseBuilder.pkiResponse(pkiResponse);
      TaggedAttribute[] responseControlSequence = CMCUtils.getResponseControlSequence(pkiResponse);
      byte[] nonce = (byte[]) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_recipientNonce, responseControlSequence).getValue();
      CMCStatusInfoV2 statusInfoV2 = (CMCStatusInfoV2) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_statusInfoV2, responseControlSequence).getValue();
      CMCResponseStatus responseStatus = getResponseStatus(statusInfoV2);
      responseBuilder
        .nonce(nonce)
        .responseStatus(responseStatus);
      if (responseStatus.getStatus().equals(CMCStatusType.success) && expectCertsOnSuccess){
        // Success response where return certificates are expected. Get return certificates
        responseBuilder.returnCertificates(getResponseCertificates(signedData, cmcValidationResult));
      } else {
        // No response success or no certificates expected in response. Return empty return certificate list
        responseBuilder.returnCertificates(new ArrayList<>());
      }
    } catch (Exception ex){
      log.debug("Error parsing PKIResponse Data from CMC response", ex.toString());
      throw new IOException("Error parsing PKIResponse Data from CMC response", ex);
    }
    return responseBuilder.build();
  }

  CMCResponseStatus getResponseStatus(CMCStatusInfoV2 statusInfoV2) {
    CMCFailType cmcFailType = getCmcFailType(statusInfoV2);
    CMCStatusType cmcStatus = CMCStatusType.getCMCStatusType(statusInfoV2.getcMCStatus());
    String statusString = statusInfoV2.getStatusString() != null
      ? statusInfoV2.getStatusString().getString()
      : null;
    BodyPartID[] bodyList = statusInfoV2.getBodyList();
    CMCResponseStatus cmcResponseStatus = new CMCResponseStatus(
      cmcStatus, cmcFailType, statusString, Arrays.asList(bodyList)
    );
    return cmcResponseStatus;
  }

  public static CMCFailType getCmcFailType(CMCStatusInfoV2 statusInfoV2) {
    OtherStatusInfo otherStatusInfo = statusInfoV2.getOtherStatusInfo();
    if (otherStatusInfo != null && otherStatusInfo.isFailInfo()){
      CMCFailInfo cmcFailInfo = CMCFailInfo.getInstance(otherStatusInfo.toASN1Primitive());
      return CMCFailType.getCMCFailType(cmcFailInfo);
    }
    return null;
  }


  /**
   * The process here is a bit complicated since the return certificates are mixed with the CMC signing certificates which may be issued
   * by the CMC CA. The algorithm is as follows:
   *
   *  1) List all certificates in the CMS signature
   *  2) Remove all certs not issued by the CA
   *  3) If more than one certificate remains, remove any trusted CMS signer certificate
   *
   * @param signedData
   * @param cmcValidationResult
   * @return
   * @throws CertificateException
   * @throws IOException
   */
  private List<X509Certificate> getResponseCertificates(CMSSignedData signedData, CMCValidationResult cmcValidationResult) throws CertificateException, IOException {
    Collection<X509CertificateHolder> certsInCMS = signedData.getCertificates().getMatches(null);
    List<X509Certificate> certificateList = new ArrayList<>();
    for (X509CertificateHolder certificateHolder: certsInCMS){
      certificateList.add(CAUtils.getCert(certificateHolder));
    }
    // Remove all certs not issued by the CA
    List<X509Certificate> caIssuedCertificateList = new ArrayList<>();
    for (X509Certificate cmsCert: certificateList) {
      try {
        cmsCert.verify(caPublicKey);
        caIssuedCertificateList.add(cmsCert);
      }
      catch (InvalidKeyException | SignatureException e) {
        continue;
      }
      catch (Exception e) {
        throw new IOException("Invalid return certificate in CMC response");
      }
    }

    if (caIssuedCertificateList.size() < 2){
      return caIssuedCertificateList;
    }

    // More than 1 remaining cert. Remove any trusted CMS signer certificate
    List<X509Certificate> filteredCertificateList = new ArrayList<>();
    List<X509Certificate> cmsSignerCertificatePath = CAUtils.getCertList(cmcValidationResult.getSignerCertificatePath());
    for (X509Certificate caIssuedCert: caIssuedCertificateList) {
      if (!cmsSignerCertificatePath.contains(caIssuedCert)){
        filteredCertificateList.add(caIssuedCert);
      }
    }
    return filteredCertificateList;
  }
}
