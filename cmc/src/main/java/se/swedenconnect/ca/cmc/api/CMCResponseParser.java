/*
 * Copyright (c) 2021. Agency for Digital Government (DIGG)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.swedenconnect.ca.cmc.api;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cmc.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import se.swedenconnect.ca.cmc.api.data.*;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.auth.CMCValidationResult;
import se.swedenconnect.ca.cmc.auth.CMCValidator;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.engine.utils.CAUtils;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Parser of CMC response data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMCResponseParser {

  /** A validator used to validate signatures on a CMC request as well as the authorization granted to the CMC signer to make this request */
  private final CMCValidator validator;
  /** The public key of the CA used to verify which of the return certificates that actually are issued by the responding CA */
  private final PublicKey caPublicKey;

  /**
   * Constructor
   * @param validator validator for validating signature on the response and the authorization of the responder
   * @param caPublicKey public key of the CA
   */
  public CMCResponseParser(CMCValidator validator, PublicKey caPublicKey) {
    this.validator = validator;
    this.caPublicKey = caPublicKey;
  }

  /**
   * Parsing a CMC response
   * @param cmcResponseBytes the bytes of a CMC response
   * @param cmcRequestType the type of CMC request this response is related to
   * @return {@link CMCResponse}
   * @throws IOException on error parsing the CMC response bytes
   */
  public CMCResponse parseCMCresponse(byte[] cmcResponseBytes, CMCRequestType cmcRequestType) throws IOException {

    CMCResponse.CMCResponseBuilder responseBuilder = CMCResponse.builder();
    responseBuilder
      .cmcResponseBytes(cmcResponseBytes)
      .cmcRequestType(cmcRequestType);

    boolean expectCertsOnSuccess;
    switch (cmcRequestType) {
    case issueCert:
    case getCert:
      expectCertsOnSuccess = true;
      break;
    default:
      expectCertsOnSuccess = false;
    }

    CMCValidationResult cmcValidationResult = validator.validateCMC(cmcResponseBytes);
    if (!CMCObjectIdentifiers.id_cct_PKIResponse.equals(cmcValidationResult.getContentType())) {
      throw new IOException("Illegal CMS content type for CMC request");
    }
    if (!cmcValidationResult.isValid()) {
      throw new IOException(cmcValidationResult.getErrorMessage(), cmcValidationResult.getException());
    }

    try {
      CMSSignedData signedData = cmcValidationResult.getSignedData();
      PKIResponse pkiResponse = PKIResponse.getInstance(
        new ASN1InputStream((byte[]) signedData.getSignedContent().getContent()).readObject());
      responseBuilder.pkiResponse(pkiResponse);
      byte[] nonce = (byte[]) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_recipientNonce, pkiResponse).getValue();
      CMCStatusInfoV2 statusInfoV2 = (CMCStatusInfoV2) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_statusInfoV2,
        pkiResponse).getValue();
      CMCResponseStatus responseStatus = getResponseStatus(statusInfoV2);
      responseBuilder
        .nonce(nonce)
        .responseStatus(responseStatus);
      if (responseStatus.getStatus().equals(CMCStatusType.success) && expectCertsOnSuccess) {
        // Success response where return certificates are expected. Get return certificates
        responseBuilder.returnCertificates(getResponseCertificates(signedData, cmcValidationResult));
      }
      else {
        // No response success or no certificates expected in response. Return empty return certificate list
        responseBuilder.returnCertificates(new ArrayList<>());
      }
    }
    catch (Exception ex) {
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
    if (otherStatusInfo != null && otherStatusInfo.isFailInfo()) {
      CMCFailInfo cmcFailInfo = CMCFailInfo.getInstance(otherStatusInfo.toASN1Primitive());
      return CMCFailType.getCMCFailType(cmcFailInfo);
    }
    return null;
  }

  /**
   * The process here is a bit complicated since the return certificates are mixed with the CMC signing certificates which may be issued
   * by the CMC CA. The algorithm is as follows:
   * <p>
   * 1) List all certificates in the CMS signature
   * 2) Remove all certs not issued by the CA
   * 3) If more than one certificate remains, remove any trusted CMS signer certificate
   *
   * @param signedData
   * @param cmcValidationResult
   * @return
   * @throws CertificateException
   * @throws IOException
   */
  private List<X509Certificate> getResponseCertificates(CMSSignedData signedData, CMCValidationResult cmcValidationResult)
    throws CertificateException, IOException {
    Collection<X509CertificateHolder> certsInCMS = signedData.getCertificates().getMatches(null);
    List<X509Certificate> certificateList = new ArrayList<>();
    for (X509CertificateHolder certificateHolder : certsInCMS) {
      certificateList.add(CAUtils.getCert(certificateHolder));
    }
    // Remove all certs not issued by the CA
    List<X509Certificate> caIssuedCertificateList = new ArrayList<>();
    for (X509Certificate cmsCert : certificateList) {
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

    if (caIssuedCertificateList.size() < 2) {
      return caIssuedCertificateList;
    }

    // More than 1 remaining cert. Remove any trusted CMS signer certificate
    List<X509Certificate> filteredCertificateList = new ArrayList<>();
    List<X509Certificate> cmsSignerCertificatePath = CAUtils.getCertList(cmcValidationResult.getSignerCertificatePath());
    for (X509Certificate caIssuedCert : caIssuedCertificateList) {
      if (!cmsSignerCertificatePath.contains(caIssuedCert)) {
        filteredCertificateList.add(caIssuedCert);
      }
    }
    return filteredCertificateList;
  }
}
