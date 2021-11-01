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

package se.swedenconnect.ca.cmc.utils;

import com.fasterxml.jackson.databind.type.CollectionType;
import org.bouncycastle.asn1.cmc.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import se.swedenconnect.ca.cmc.api.data.CMCControlObject;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.admin.AdminRequestType;
import se.swedenconnect.ca.cmc.model.admin.request.ListCerts;
import se.swedenconnect.ca.cmc.model.admin.response.CAInformation;
import se.swedenconnect.ca.cmc.model.admin.response.CertificateData;
import se.swedenconnect.ca.cmc.model.request.CMCRequestModel;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.cmc.model.request.impl.CMCAdminRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCCertificateRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCGetCertRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCRevokeRequestModel;
import se.swedenconnect.ca.cmc.model.response.CMCResponseModel;
import se.swedenconnect.ca.engine.utils.CAUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCDataValidator {

  public static CollectionType certDataListType = CMCUtils.OBJECT_MAPPER.getTypeFactory()
    .constructCollectionType(List.class, CertificateData.class);
  public static CollectionType bigIntListType = CMCUtils.OBJECT_MAPPER.getTypeFactory()
    .constructCollectionType(List.class, BigInteger.class);

  public static void validateCMCRequest(CMCRequest cmcRequest, CMCRequestModel requestModel) throws IOException, ParseException {
    CMCRequestType cmcRequestType = requestModel.getCmcRequestType();
    PKIData pkiData = cmcRequest.getPkiData();

    // Check nonce
    if (!Arrays.equals(cmcRequest.getNonce(), requestModel.getNonce())) {
      throw new IOException("Nonce mismatch");
    }

    // Check request type
    if (cmcRequestType == null || !cmcRequestType.equals(cmcRequest.getCmcRequestType())) {
      throw new IOException("Request type mismatch");
    }

    // Check cert request data
    if (CMCRequestType.issueCert.equals(cmcRequestType)) {
      CertificationRequest p10Request = cmcRequest.getCertificationRequest();
      CertificateRequestMessage crmfRequest = cmcRequest.getCertificateRequestMessage();
      if (p10Request == null && crmfRequest == null) {
        throw new IOException("No valid request");
      }
      CMCCertificateRequestModel certReqModel = (CMCCertificateRequestModel) requestModel;
      if (certReqModel.getCertReqPrivate() == null && certReqModel.getP10Algorithm() == null) {
        if (crmfRequest == null) {
          throw new IOException("No cert request signing key and algorithm. Request must be CRMF but no such request was created");
        }
      }
      else {
        if (p10Request == null) {
          throw new IOException(
            "Cert request private key and/or cert request signing algorithm was provided, but no PKCS#10 request was created");
        }
      }

      // Ensure that a cert request body part ID was recorded
      long certReqBPIDVal = cmcRequest.getCertReqBodyPartId().getID();

      // Check LRA pop whiteness
      if (certReqModel.isLraPopWitness()) {
        CMCControlObject lpwObj = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_lraPOPWitness, pkiData);
        LraPopWitness lpw = (LraPopWitness) lpwObj.getValue();
        BodyPartID[] bodyIds = lpw.getBodyIds();
        if (certReqBPIDVal != bodyIds[0].getID()) {
          throw new IOException("LRA POP Witness cert request ID does not match cert request");
        }
      }
    }

    // Check revocation request data
    if (CMCRequestType.revoke.equals(cmcRequestType)) {
      RevokeRequest revokeRequest = (RevokeRequest) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_revokeRequest, pkiData)
        .getValue();
      CMCRevokeRequestModel revokeReqModel = (CMCRevokeRequestModel) requestModel;
      if (!revokeReqModel.getIssuerName().equals(revokeRequest.getName())) {
        throw new IOException("Certificate issuer DN mismatch in CMC revoke request");
      }
      if (!revokeReqModel.getSerialNumber().equals(revokeRequest.getSerialNumber())) {
        throw new IOException("Certificate serial number mismatch in CMC revoke request");
      }
      long modelRevTimeSec = revokeReqModel.getRevocationDate().getTime() / 1000;
      long revTimeSec = revokeRequest.getInvalidityDate().getDate().getTime() / 1000;
      if (modelRevTimeSec != revTimeSec) {
        Date modelRevocationDate = revokeReqModel.getRevocationDate();
        Date revokeDate = revokeRequest.getInvalidityDate().getDate();
        throw new IOException(
          "Certificate revocation date mismatch CMC revoke request - expected: " + modelRevocationDate + " found: " + revokeDate);
      }
      if (revokeReqModel.getReason() != revokeRequest.getReason().getValue().intValue()) {
        throw new IOException("Certificate serial number mismatch in CMC revoke request");
      }
    }

    // Check get cert data
    if (CMCRequestType.getCert.equals(cmcRequestType)) {
      GetCert getCert = (GetCert) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_getCert, pkiData).getValue();
      CMCGetCertRequestModel getCertReqModel = (CMCGetCertRequestModel) requestModel;

      if (!getCertReqModel.getIssuerName().equals(X500Name.getInstance(getCert.getIssuerName().getName()))) {
        throw new IOException("Certificate issuer DN mismatch in CMC get cert request");
      }
      if (!getCertReqModel.getSerialNumber().equals(getCert.getSerialNumber())) {
        throw new IOException("Certificate serial number mismatch in CMC get cert request");
      }
    }

    // Check admin request data
    if (CMCRequestType.admin.equals(cmcRequestType)) {
      AdminCMCData adminCMCData = (AdminCMCData) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_regInfo, pkiData).getValue();
      CMCAdminRequestModel adminReqModel = (CMCAdminRequestModel) requestModel;
      AdminRequestType adminRequestType = adminCMCData.getAdminRequestType();
      if (adminRequestType == null) {
        throw new IOException("Admin request type must be specified in Admin request data");
      }
      AdminCMCData modelAdminData = CMCUtils.OBJECT_MAPPER.readValue(adminReqModel.getRegistrationInfo(), AdminCMCData.class);

      if (!adminRequestType.equals(modelAdminData.getAdminRequestType())) {
        throw new IOException("Admin request type mismatch");
      }
      switch (adminRequestType) {
      case caInfo:
        if (adminCMCData.getData() != null) {
          throw new IOException("Illegal admin request data for ca info request - Expected null");
        }
        break;
      case allCertSerials:
        if (adminCMCData.getData() != null) {
          throw new IOException("Illegal admin request data for all cert serial request - Expected null");
        }
        break;
      case listCerts:
        ListCerts listCerts = CMCUtils.OBJECT_MAPPER.readValue(adminCMCData.getData(), ListCerts.class);
        ListCerts modelListCerts = CMCUtils.OBJECT_MAPPER.readValue(modelAdminData.getData(), ListCerts.class);
        if (listCerts.isNotRevoked() ^ modelListCerts.isNotRevoked()) {
          throw new IOException("Admin request data for list cert mismatch - isValid mismatch");
        }
        if (listCerts.getPageIndex() != modelListCerts.getPageIndex()) {
          throw new IOException("Admin request data for list cert mismatch - pageIndex mismatch");
        }
        if (listCerts.getPageSize() != modelListCerts.getPageSize()) {
          throw new IOException("Admin request data for list cert mismatch - pageSize mismatch");
        }
        if (!listCerts.getSortBy().equals(modelListCerts.getSortBy())) {
          throw new IOException("Admin request data for list cert mismatch - sortBy mismatch");
        }
        break;
      }
    }
  }

  public static void validateCMCResponse(CMCResponse cmcResponse, CMCResponseModel responseModel)
    throws IOException, CMSException, CertificateException {

    PKIResponse pkiResponse = cmcResponse.getPkiResponse();

    // Check nonce
    if (Arrays.compare(cmcResponse.getNonce(), cmcResponse.getNonce()) != 0) {
      throw new IOException("Nonce mismatch");
    }

      //Check return certificates
      List<X509Certificate> returnCertificates = responseModel.getReturnCertificates();
    CMSSignedData cmsSignedData = new CMSSignedData(cmcResponse.getCmcResponseBytes());
    Collection<X509CertificateHolder> certsInCMS = cmsSignedData.getCertificates().getMatches(null);

    if (returnCertificates != null && !returnCertificates.isEmpty()) {
      // response model contains return certificates. Verify that all of them is present in the CMS certs
      for (X509Certificate returnCert : returnCertificates) {
        // Make sure all of these are in the CMS certs field
        boolean present = false;
        for (X509CertificateHolder certHoldserInCms : certsInCMS) {
          X509Certificate certInCms = CAUtils.getCert(certHoldserInCms);
          if (certInCms.equals(returnCert)) {
            present = true;
          }
        }
        if (!present) {
          throw new IOException("Certificate in response model not present in CMS bag of certs");
        }
      }
    }

    // Check control messages
    // Check the mandatory status message
    List<BodyPartID> processedRequestObjects = responseModel.getCmcResponseStatus().getBodyPartIDList();
    CMCStatusInfoV2 statusInfo = (CMCStatusInfoV2) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_statusInfoV2,
      pkiResponse).getValue();
    CMCResponseStatus cmcResponseStatus = responseModel.getCmcResponseStatus();
    if (!cmcResponseStatus.getStatus().getCmcStatus().equals(statusInfo.getcMCStatus())) {
      throw new IOException("Response status mismatch");
    }
    // Check processed body part ID:s

    for (BodyPartID reqObjId : processedRequestObjects) {
      boolean present = Arrays.stream(statusInfo.getBodyList())
        .anyMatch(bodyPartID -> bodyPartID.equals(reqObjId));
      if (!present) {
        throw new IOException("Processed body part ID declaration not present");
      }
    }
    if (cmcResponseStatus.getFailType() != null) {
      if (!cmcResponseStatus.getFailType().getCmcFailInfo().equals(CMCDataPrint.getCmcFailType(statusInfo).getCmcFailInfo())) {
        throw new IOException("Response fail type mismatch");
      }
    }
    if (cmcResponseStatus.getMessage() != null) {
      if (!cmcResponseStatus.getMessage().equals(statusInfo.getStatusString().getString())) {
        throw new IOException("Response fail type mismatch");
      }
    }

    // Check response data
    CMCControlObject cmcControlObject = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_responseInfo, pkiResponse);
    Object respInfoObj = cmcControlObject.getValue();
    if (respInfoObj instanceof AdminCMCData) {
      AdminCMCData adminCMCData = (AdminCMCData) respInfoObj;
      AdminCMCData modelAdminCMCData = CMCUtils.OBJECT_MAPPER.readValue(responseModel.getResponseInfo(), AdminCMCData.class);
      AdminRequestType adminRequestType = adminCMCData.getAdminRequestType();
      if (!adminRequestType.equals(modelAdminCMCData.getAdminRequestType())) {
        throw new IOException("Admin data type mismatch");
      }
      switch (adminRequestType) {
      case caInfo:
        CAInformation caInformation = CMCUtils.OBJECT_MAPPER.readValue(adminCMCData.getData(), CAInformation.class);
        CAInformation modelCaInformation = CMCUtils.OBJECT_MAPPER.readValue(modelAdminCMCData.getData(), CAInformation.class);
        if (caInformation.getCertificateChain().size() != modelCaInformation.getCertificateChain().size()) {
          throw new IOException("CA chain size mismatch");
        }
        if (caInformation.getCertificateCount() != modelCaInformation.getCertificateCount()) {
          throw new IOException("CA certificate count mismatch");
        }
        if (modelCaInformation.getOcspCertificate() != null) {
          if (!Arrays.equals(modelCaInformation.getOcspCertificate(), caInformation.getOcspCertificate())) {
            throw new IOException("OCSP certificate mismatch");
          }
        }
        if (modelCaInformation.getValidCertificateCount() != caInformation.getValidCertificateCount()) {
          throw new IOException("Valid certificate count mismatch");
        }
        break;
      case listCerts:
        List<CertificateData> certDataList = CMCUtils.OBJECT_MAPPER.readValue(adminCMCData.getData(), certDataListType);
        List<CertificateData> modelCertDataList = CMCUtils.OBJECT_MAPPER.readValue(adminCMCData.getData(), certDataListType);
        if (certDataList.size() != modelCertDataList.size()) {
          throw new IOException("Cert data list size mismatch");
        }
        break;
      case allCertSerials:
        List<BigInteger> allSerialsList = CMCUtils.OBJECT_MAPPER.readValue(adminCMCData.getData(), bigIntListType);
        List<BigInteger> modelallSerialsList = CMCUtils.OBJECT_MAPPER.readValue(adminCMCData.getData(), bigIntListType);
        if (allSerialsList.size() != modelallSerialsList.size()) {
          throw new IOException("All cert serials list size mismatch");
        }
        break;
      }
    }
    else {
      byte[] respInfoBytes = (byte[]) respInfoObj;
      if (!Arrays.equals(respInfoBytes, responseModel.getResponseInfo())) {
        throw new IOException("Response info bytes mismatch");
      }
    }
  }
}
