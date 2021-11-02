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

package se.swedenconnect.ca.cmc.api.impl;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.cmc.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.cmc.api.*;
import se.swedenconnect.ca.cmc.api.data.*;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.cmc.model.response.CMCResponseModel;
import se.swedenconnect.ca.cmc.model.response.impl.CMCAdminResponseModel;
import se.swedenconnect.ca.cmc.model.response.impl.CMCBasicCMCResponseModel;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;
import se.swedenconnect.ca.engine.utils.CAUtils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Basic abstract CMC CA API implementation
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractCMCCaApi implements CMCCaApi {

  protected final CAService caService;
  protected final CMCRequestParser cmcRequestParser;
  protected final CMCResponseFactory cmcResponseFactory;

  public AbstractCMCCaApi(CAService caService, CMCRequestParser cmcRequestParser,
    CMCResponseFactory cmcResponseFactory) {
    this.caService = caService;
    this.cmcRequestParser = cmcRequestParser;
    this.cmcResponseFactory = cmcResponseFactory;
  }

  @Override public CMCResponse processRequest(byte[] cmcRequestBytes) {

    byte[] nonce = new byte[]{};

    try {
      CMCRequest cmcRequest = cmcRequestParser.parseCMCrequest(cmcRequestBytes);
      nonce = cmcRequest.getNonce();
      CMCRequestType cmcRequestType = cmcRequest.getCmcRequestType();
      switch (cmcRequestType) {

      case issueCert:
        return processCertIssuingRequest(cmcRequest);
      case revoke:
        return processRevokeRequest(cmcRequest);
      case admin:
        return processCustomRequest(cmcRequest);
      case getCert:
        return processGetCertRequest(cmcRequest);
      default:
        throw new IllegalArgumentException("Unrecognized CMC request type");
      }
    }
    catch (Exception ex) {
      try {
        if (ex instanceof CMCParsingException) {
          CMCParsingException cmcParsingException = (CMCParsingException) ex;
          CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
            cmcParsingException.getNonce(),
            CMCResponseStatus.builder()
              .status(CMCStatusType.failed)
              .failType(CMCFailType.badRequest)
              .message(ex.getMessage())
              .bodyPartIDList(new ArrayList<>())
              .build(),
            null, null
          );
          return cmcResponseFactory.getCMCResponse(responseModel);
        }
        if (ex instanceof CMCCaApiException) {
          // Processing CMC request resulted in a error exception.
          CMCCaApiException cmcException = (CMCCaApiException) ex;
          CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
            nonce,
            CMCResponseStatus.builder()
              .status(CMCStatusType.failed)
              .failType(cmcException.getCmcFailType())
              .message(ex.getMessage())
              .bodyPartIDList(cmcException.getFailingBodyPartIds())
              .build(),

            null, null
          );
          return cmcResponseFactory.getCMCResponse(responseModel);
        }
        else {
          // Processing CMC request resulted in a general exception caused by internal CA error.
          CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
            nonce,
            CMCResponseStatus.builder()
              .status(CMCStatusType.failed)
              .failType(CMCFailType.internalCAError)
              .message(ex.getMessage())
              .bodyPartIDList(new ArrayList<>())
              .build(),

            null, null
          );
          return cmcResponseFactory.getCMCResponse(responseModel);
        }
      }
      catch (Exception e) {
        // This should never happen unless there is a serious bug or configuration error
        // The exception caught here is related to parsing returnCertificates which is passed as a null parameter in this case
        e.printStackTrace();
        log.error("Critical exception in CA API implementation", e);
        throw new RuntimeException("Critical exception in CA API implementation", e);
      }
    }
  }

  protected CMCResponse processCertIssuingRequest(CMCRequest cmcRequest) throws CMCCaApiException {

    try {
      CertificateModel certificateModel = getCertificateModel(cmcRequest);
      X509CertificateHolder certificateHolder = caService.issueCertificate(certificateModel);

      CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
        cmcRequest.getNonce(),
        new CMCResponseStatus(CMCStatusType.success, Arrays.asList(cmcRequest.getCertReqBodyPartId())),
        cmcRequest.getCmcRequestType(),
        (byte[]) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_regInfo, cmcRequest.getPkiData()).getValue(),
        Arrays.asList(certificateHolder)
      );

      return cmcResponseFactory.getCMCResponse(responseModel);
    }
    catch (Exception ex) {
      List<BodyPartID> failingBodyPartIds = cmcRequest.getCertReqBodyPartId() == null
        ? new ArrayList<>()
        : Arrays.asList(cmcRequest.getCertReqBodyPartId());
      throw new CMCCaApiException(ex, failingBodyPartIds, CMCFailType.badRequest);
    }
  }

  /**
   * This functions generates a certificate request model from the certificate request and control parameters from a CMC request
   *
   * @param cmcRequest CMC Request
   * @return certificate model
   * @throws Exception Any exception caught while attempting to create a certificate model from the CMC request
   */
  abstract CertificateModel getCertificateModel(CMCRequest cmcRequest) throws Exception;

  protected CMCResponse processRevokeRequest(CMCRequest cmcRequest) throws CMCCaApiException {
    try {
      PKIData pkiData = cmcRequest.getPkiData();
      CMCControlObject cmcControlObject = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_revokeRequest, pkiData);
      BodyPartID revokeBodyPartId = cmcControlObject.getBodyPartID();
      RevokeRequest revokeRequest = (RevokeRequest) cmcControlObject.getValue();
      // Check issuer name
      final X500Name issuerName = revokeRequest.getName();
      if (caService.getCaCertificate().getSubject().equals(issuerName)) {
        Date revokeDate = revokeRequest.getInvalidityDate().getDate();
        int reason = revokeRequest.getReason().getValue().intValue();
        BigInteger serialNumber = revokeRequest.getSerialNumber();

        try {
          caService.revokeCertificate(serialNumber, reason, revokeDate);
        } catch (Exception ex2) {
          throw new CMCCaApiException(ex2.getMessage(), ex2, Arrays.asList(revokeBodyPartId), CMCFailType.badCertId);
        }
        CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
          cmcRequest.getNonce(),
          new CMCResponseStatus(CMCStatusType.success, Arrays.asList(revokeBodyPartId)), null, null
        );
        return cmcResponseFactory.getCMCResponse(responseModel);
      } else {
        throw new CMCCaApiException("Revocation request does not match CA issuer name", Arrays.asList(revokeBodyPartId), CMCFailType.badRequest);
      }
    } catch (Exception ex) {
      if (ex instanceof CMCCaApiException) {
        throw (CMCCaApiException) ex;
      }
      throw new CMCCaApiException(ex, new ArrayList<>(), CMCFailType.badRequest);
    }
  }

  protected CMCResponse processCustomRequest(CMCRequest cmcRequest) throws Exception {
    PKIData pkiData = cmcRequest.getPkiData();
    CMCControlObject cmcControlObject = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_regInfo, pkiData);
    AdminCMCData adminRequest = (AdminCMCData) cmcControlObject.getValue();
    AdminCMCData adminResponse = getAdminResponse(adminRequest);
    CMCResponseModel responseModel = new CMCAdminResponseModel(
      cmcRequest.getNonce(),
      new CMCResponseStatus(CMCStatusType.success, Arrays.asList(cmcControlObject.getBodyPartID())),
      cmcRequest.getCmcRequestType(),
      adminResponse
    );

    return cmcResponseFactory.getCMCResponse(responseModel);
  }

  protected abstract AdminCMCData getAdminResponse(AdminCMCData adminRequest) throws Exception;

  protected CMCResponse processGetCertRequest(CMCRequest cmcRequest) throws CMCCaApiException {
    List<BodyPartID> requestBodyParts = new ArrayList<>();
    try {
      PKIData pkiData = cmcRequest.getPkiData();
      CMCControlObject cmcControlObject = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_getCert, pkiData);
      requestBodyParts = Arrays.asList(cmcControlObject.getBodyPartID());
      GetCert getCert = (GetCert) cmcControlObject.getValue();
      X500Name issuerName = (X500Name) getCert.getIssuerName().getName();
      if (caService.getCaCertificate().getSubject().equals(issuerName)) {
        CertificateRecord certificateRecord = caService.getCaRepository().getCertificate(getCert.getSerialNumber());
        X509CertificateHolder targetCertificateHolder = new X509CertificateHolder(certificateRecord.getCertificate());
        CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
          cmcRequest.getNonce(),
          new CMCResponseStatus(CMCStatusType.success, requestBodyParts),
          cmcRequest.getCmcRequestType(), null,
          Arrays.asList(CAUtils.getCert(targetCertificateHolder))
        );
        return cmcResponseFactory.getCMCResponse(responseModel);
      }
    } catch (Exception ex) {
      throw new CMCCaApiException("Failure to process Get Cert reqeust", ex, requestBodyParts, CMCFailType.badRequest);
    }
    throw new CMCCaApiException("Get certificate request does not match CA issuer name", requestBodyParts, CMCFailType.badRequest);
  }

}
