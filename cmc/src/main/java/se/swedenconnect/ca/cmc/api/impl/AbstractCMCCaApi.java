package se.swedenconnect.ca.cmc.api.impl;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.cmc.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.cmc.api.CMCCaApi;
import se.swedenconnect.ca.cmc.api.CMCRequestParser;
import se.swedenconnect.ca.cmc.api.CMCResponseFactory;
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
import java.util.Arrays;
import java.util.Date;

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

  @Override public CMCResponse processRequest(CMCRequest cmcRequest) {

    try {
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
        // Processing CMC request resulted in an exception. Return
        CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
          cmcRequest.getNonce(),
          CMCResponseStatus.builder()
            .status(CMCStatusType.failed)
            .failType(CMCFailType.badRequest)
            .message(ex.getMessage())
            .bodyPartIDList(Arrays.asList(cmcRequest.getCertReqBodyPartId()))
            .build(),

          null, null
        );
        return cmcResponseFactory.getCMCResponse(responseModel);
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

  protected CMCResponse processCertIssuingRequest(CMCRequest cmcRequest) throws Exception {

    CertificateModel certificateModel = getCertificateModel(cmcRequest);
    X509CertificateHolder certificateHolder = caService.issueCertificate(certificateModel);

    CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
      cmcRequest.getNonce(),
      new CMCResponseStatus(CMCStatusType.success, Arrays.asList(cmcRequest.getCertReqBodyPartId())),
      (byte[]) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_regInfo, cmcRequest.getPkiData()).getValue(),
      Arrays.asList(certificateHolder)
    );

    return cmcResponseFactory.getCMCResponse(responseModel);
  }

  /**
   * This functions generates a certificate request model from the certificate request and control parameters from a CMC request
   *
   * @param cmcRequest CMC Request
   * @return certificate model
   * @throws Exception Any exception caught while attempting to create a certificate model from the CMC request
   */
  abstract CertificateModel getCertificateModel(CMCRequest cmcRequest) throws Exception;

  protected CMCResponse processRevokeRequest(CMCRequest cmcRequest) throws Exception {
    PKIData pkiData = cmcRequest.getPkiData();
    CMCControlObject cmcControlObject = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_revokeRequest, pkiData);
    BodyPartID revokeBodyPartId = cmcControlObject.getBodyPartID();
    RevokeRequest revokeRequest = (RevokeRequest) cmcControlObject.getValue();
    Date revokeDate = revokeRequest.getInvalidityDate().getDate();
    int reason = revokeRequest.getReason().getValue().intValue();
    BigInteger serialNumber = revokeRequest.getSerialNumber();
    caService.revokeCertificate(serialNumber, reason, revokeDate);
    CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
      cmcRequest.getNonce(),
      new CMCResponseStatus(CMCStatusType.success, Arrays.asList(revokeBodyPartId)), null, null
    );
    return cmcResponseFactory.getCMCResponse(responseModel);
  }

  protected CMCResponse processCustomRequest(CMCRequest cmcRequest) throws Exception {
    PKIData pkiData = cmcRequest.getPkiData();
    CMCControlObject cmcControlObject = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_getCert, pkiData);
    AdminCMCData adminRequest = (AdminCMCData) cmcControlObject.getValue();
    AdminCMCData adminResponse = getAdminResponse(adminRequest);
    CMCResponseModel responseModel = new CMCAdminResponseModel(
      cmcRequest.getNonce(),
      new CMCResponseStatus(CMCStatusType.success, Arrays.asList(cmcControlObject.getBodyPartID())),
      adminResponse
    );

    return cmcResponseFactory.getCMCResponse(responseModel);
  }

  protected abstract AdminCMCData getAdminResponse(AdminCMCData adminRequest) throws Exception;

  protected CMCResponse processGetCertRequest(CMCRequest cmcRequest) throws Exception {
    PKIData pkiData = cmcRequest.getPkiData();
    CMCControlObject cmcControlObject = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_getCert, pkiData);
    GetCert getCert = (GetCert) cmcControlObject.getValue();
    X500Name issuerName = (X500Name) getCert.getIssuerName().getName();
    if (caService.getCaCertificate().getIssuer().equals(issuerName)) {
      CertificateRecord certificateRecord = caService.getCaRepository().getCertificate(getCert.getSerialNumber());
      X509CertificateHolder targetCertificateHolder = new X509CertificateHolder(certificateRecord.getCertificate());
      CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
        cmcRequest.getNonce(),
        new CMCResponseStatus(CMCStatusType.success, Arrays.asList(cmcControlObject.getBodyPartID()))
        , null,
        Arrays.asList(CAUtils.getCert(targetCertificateHolder))
      );
      return cmcResponseFactory.getCMCResponse(responseModel);
    }
    throw new IllegalArgumentException("Get certificate request does not match CA issuer name");
  }

}
