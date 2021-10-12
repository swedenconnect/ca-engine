package se.swedenconnect.ca.cmc;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.swedenconnect.ca.cmc.api.CMCRequestFactory;
import se.swedenconnect.ca.cmc.api.CMCRequestParser;
import se.swedenconnect.ca.cmc.api.CMCResponseFactory;
import se.swedenconnect.ca.cmc.api.CMCResponseParser;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.auth.impl.DefaultCMCValidator;
import se.swedenconnect.ca.cmc.ca.*;
import se.swedenconnect.ca.cmc.data.CMCRequestData;
import se.swedenconnect.ca.cmc.data.TestResponseStatus;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.admin.AdminRequestType;
import se.swedenconnect.ca.cmc.model.admin.response.CAInformation;
import se.swedenconnect.ca.cmc.model.admin.response.CertificateData;
import se.swedenconnect.ca.cmc.model.request.CMCRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCAdminRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCCertificateRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCGetCertRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCRevokeRequestModel;
import se.swedenconnect.ca.cmc.model.response.CMCResponseModel;
import se.swedenconnect.ca.cmc.model.response.impl.CMCAdminResponseModel;
import se.swedenconnect.ca.cmc.model.response.impl.CMCBasicCMCResponseModel;
import se.swedenconnect.ca.cmc.utils.CMCDataValidator;
import se.swedenconnect.ca.cmc.utils.CMCSigner;
import se.swedenconnect.ca.cmc.utils.CMCDataPrint;
import se.swedenconnect.ca.cmc.utils.TestUtils;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMCTests {

  private static SecureRandom RNG = new SecureRandom();
  private static CMCSigner cmcSigner;
  private static final ObjectMapper objectMapper = new ObjectMapper();
  private static X509CertificateHolder testCert01;
  private static X509CertificateHolder testCert02;
  private static X509CertificateHolder testCert03;

  /**
   * Initializes the CA services used to provide certificates and revocation services based on this library
   */
  @BeforeAll
  public static void init() {
    Security.addProvider(new BouncyCastleProvider());
    log.info("Setting up test CA:s");
    TestServices.addCa(TestCA.INSTANCE1);
    TestServices.addCa(TestCA.RA_CA);
    TestServices.addCa(TestCA.ECDSA_CA);
    TestServices.addValidators(true);

    try {
      KeyPair raKeyPair = TestUtils.generateECKeyPair(TestUtils.NistCurve.P256);
      TestCAHolder raCaHolder = TestServices.getTestCAs().get(TestCA.RA_CA);
      TestCAService raSignerCA = raCaHolder.getCscaService();
      CertificateModel certificateModel = raSignerCA.getCertificateModelBuilder(
        CertRequestData.getTypicalServiceName("RA Signer", "XX"), raKeyPair.getPublic()).build();
      X509CertificateHolder raCert = raSignerCA.issueCertificate(certificateModel);
      cmcSigner = new CMCSigner(raKeyPair, TestUtils.getCertificate(raCert.getEncoded()));

      TestCAHolder caHolder = TestServices.getTestCAs().get(TestCA.INSTANCE1);
      TestCAService ca = caHolder.getCscaService();

      KeyPair subjectKeyPair1 = TestUtils.generateECKeyPair(TestUtils.NistCurve.P256);
      DefaultCertificateModelBuilder subj1CertModelBuilder = ca.getCertificateModelBuilder(
        CMCRequestData.subjectMap.get(CMCRequestData.USER1), subjectKeyPair1.getPublic());
      testCert01 = ca.issueCertificate(subj1CertModelBuilder.build());
      KeyPair subjectKeyPair2 = TestUtils.generateECKeyPair(TestUtils.NistCurve.P256);
      DefaultCertificateModelBuilder subj2CertModelBuilder = ca.getCertificateModelBuilder(
        CMCRequestData.subjectMap.get(CMCRequestData.USER2), subjectKeyPair2.getPublic());
      testCert02 = ca.issueCertificate(subj1CertModelBuilder.build());
      KeyPair subjectKeyPair3 = TestUtils.generateECKeyPair(TestUtils.NistCurve.P256);
      DefaultCertificateModelBuilder subj3CertModelBuilder = ca.getCertificateModelBuilder(
        CMCRequestData.subjectMap.get(CMCRequestData.USER3), subjectKeyPair3.getPublic());
      testCert03 = ca.issueCertificate(subj1CertModelBuilder.build());

    }
    catch (Exception e) {
      e.printStackTrace();
    }

  }

  @Test
  public void checkCMCRequest() throws Exception {

    TestCAHolder caHolder = TestServices.getTestCAs().get(TestCA.INSTANCE1);
    TestCAService ca = caHolder.getCscaService();
    KeyPair subjectKeyPair = TestUtils.generateECKeyPair(TestUtils.NistCurve.P256);

    DefaultCertificateModelBuilder certificateModelBuilder = ca.getCertificateModelBuilder(
      CMCRequestData.subjectMap.get(CMCRequestData.USER1), subjectKeyPair.getPublic());
    CertificateModel certificateModel = certificateModelBuilder.build();
    //X509CertificateHolder testCert01 = ca.issueCertificate(certificateModel);

    CMCRequestFactory cmcRequestFactory = new CMCRequestFactory(cmcSigner.getSignerChain(), cmcSigner.getContentSigner());
    CMCRequestParser cmcRequestParser = new CMCRequestParser(new DefaultCMCValidator(cmcSigner.getSignerChain().get(0)));

    CMCRequestModel requestModel;
    CMCRequest cmcRequest;
    CMCRequest cmcParsed;
    //Create certificate request with PKCS#10

    requestModel = getCMCRequest(ca, certificateModel, subjectKeyPair, false, cmcRequestFactory);
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC Certificate request with PKCS#10:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcParsed = cmcRequestParser.parseCMCrequest(cmcRequest.getCmcRequestBytes());
    log.info("Parsed CMC Certificate request with PKCS#10:\n{}", CMCDataPrint.printCMCRequest(cmcParsed, false, false));
    CMCDataValidator.validateCMCRequest(cmcParsed, requestModel);

    //Create certificate request with CRMF
    requestModel = getCMCRequest(ca, certificateModel, subjectKeyPair, true, cmcRequestFactory);
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC Certificate request with CRMF:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcParsed = cmcRequestParser.parseCMCrequest(cmcRequest.getCmcRequestBytes());
    log.info("Parsed CMC Certificate request with CRMF:\n{}", CMCDataPrint.printCMCRequest(cmcParsed, false, false));
    CMCDataValidator.validateCMCRequest(cmcParsed, requestModel);

    //Create CMC revoke request
    BigInteger certSerial = testCert01.getSerialNumber();
    requestModel = new CMCRevokeRequestModel(certSerial, CRLReason.unspecified, new Date(), ca.getCaCertificate().getSubject());
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC Revoke request:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcParsed = cmcRequestParser.parseCMCrequest(cmcRequest.getCmcRequestBytes());
    log.info("Parsed CMC Revoke request:\n{}", CMCDataPrint.printCMCRequest(cmcParsed, false, false));
    CMCDataValidator.validateCMCRequest(cmcParsed, requestModel);

    //Create CMC Get Cert request
    requestModel = new CMCGetCertRequestModel(certSerial, ca.getCaCertificate().getSubject());
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC Get Cert request:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcParsed = cmcRequestParser.parseCMCrequest(cmcRequest.getCmcRequestBytes());
    log.info("Parsed CMC Get Cert request:\n{}", CMCDataPrint.printCMCRequest(cmcParsed, false, false));
    CMCDataValidator.validateCMCRequest(cmcParsed, requestModel);

    //Create CMC Admin request - CA Info
    requestModel = new CMCAdminRequestModel(CMCRequestData.adminRequestMap.get(CMCRequestData.CA_INFO));
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC Admin request - CA Info:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcParsed = cmcRequestParser.parseCMCrequest(cmcRequest.getCmcRequestBytes());
    log.info("Parsed Admin request - CA Info:\n{}", CMCDataPrint.printCMCRequest(cmcParsed, false, false));
    CMCDataValidator.validateCMCRequest(cmcParsed, requestModel);

    //Create CMC Admin request - list certs
    requestModel = new CMCAdminRequestModel(CMCRequestData.adminRequestMap.get(CMCRequestData.LIST_CERTS));
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC Admin request - List Certs:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcParsed = cmcRequestParser.parseCMCrequest(cmcRequest.getCmcRequestBytes());
    log.info("Parsed Admin request - List Certs:\n{}", CMCDataPrint.printCMCRequest(cmcParsed, false, false));
    CMCDataValidator.validateCMCRequest(cmcParsed, requestModel);

    //Create CMC Admin request - list all serials
    requestModel = new CMCAdminRequestModel(CMCRequestData.adminRequestMap.get(CMCRequestData.LIST_CERT_SERIALS));
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC Admin request - List All Serials:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcParsed = cmcRequestParser.parseCMCrequest(cmcRequest.getCmcRequestBytes());
    log.info("Parsed Admin request - List All Serials:\n{}", CMCDataPrint.printCMCRequest(cmcParsed, false, false));
    CMCDataValidator.validateCMCRequest(cmcParsed, requestModel);

  }

  @Test
  public void checkCMCResponses() throws Exception {
    TestCAHolder caHolder = TestServices.getTestCAs().get(TestCA.INSTANCE1);
    TestCAService ca = caHolder.getCscaService();

    CMCResponseFactory cmcResponseFactory = new CMCResponseFactory(cmcSigner.getSignerChain(), cmcSigner.getContentSigner());
    CMCResponseParser cmcResponseParser = new CMCResponseParser(new DefaultCMCValidator(cmcSigner.getSignerChain().get(0)));

    CMCResponseModel responseModel;
    CMCResponse cmcResponse;
    CMCResponse cmcParsed;

    byte[] nonce = new byte[128];
    RNG.nextBytes(nonce);
    List<BodyPartID> processedObjects = Arrays.asList(
      new BodyPartID(Long.valueOf("1134")),
      new BodyPartID(Long.valueOf("1234")),
      new BodyPartID(Long.valueOf("345"))
    );

    responseModel = new CMCBasicCMCResponseModel(nonce, TestResponseStatus.success.getResponseStatus(), processedObjects,
      "profile".getBytes(
        StandardCharsets.UTF_8), Arrays.asList(testCert01));
    cmcResponse = cmcResponseFactory.getCMCResponse(responseModel);
    log.info("CMC Success response:\n{}", CMCDataPrint.printCMCResponse(cmcResponse, true));
    CMCDataValidator.validateCMCResponse(cmcResponse, responseModel);
    cmcParsed = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes());
    log.info("Parsed CMC Success response:\n{}", CMCDataPrint.printCMCResponse(cmcParsed, false));
    CMCDataValidator.validateCMCResponse(cmcParsed, responseModel);

    responseModel = new CMCBasicCMCResponseModel(nonce, TestResponseStatus.failBadRequest.getResponseStatus(), processedObjects, "profile".getBytes(
        StandardCharsets.UTF_8), Arrays.asList(testCert01));
    cmcResponse = cmcResponseFactory.getCMCResponse(responseModel);
    log.info("CMC Fail response:\n{}", CMCDataPrint.printCMCResponse(cmcResponse, true));
    CMCDataValidator.validateCMCResponse(cmcResponse, responseModel);
    cmcParsed = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes());
    log.info("Parsed CMC Success response:\n{}", CMCDataPrint.printCMCResponse(cmcParsed, false));
    CMCDataValidator.validateCMCResponse(cmcParsed, responseModel);

    responseModel = new CMCAdminResponseModel(nonce, TestResponseStatus.success.getResponseStatus(), processedObjects, AdminCMCData.builder()
        .adminRequestType(AdminRequestType.caInfo)
        .data(CMCUtils.OBJECT_MAPPER.writeValueAsString(CAInformation.builder()
            .certificateChain(Arrays.asList(ca.getCaCertificate().getEncoded()))
            .certificateCount(125)
            .validCertificateCount(102)
          .build()))
        .build());
    cmcResponse = cmcResponseFactory.getCMCResponse(responseModel);
    log.info("CMC CA info response:\n{}", CMCDataPrint.printCMCResponse(cmcResponse, true));
    CMCDataValidator.validateCMCResponse(cmcResponse, responseModel);
    cmcParsed = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes());
    log.info("Parsed CA info response:\n{}", CMCDataPrint.printCMCResponse(cmcParsed, false));
    CMCDataValidator.validateCMCResponse(cmcParsed, responseModel);

    responseModel = new CMCAdminResponseModel(nonce, TestResponseStatus.success.getResponseStatus(), processedObjects, AdminCMCData.builder()
        .adminRequestType(AdminRequestType.listCerts)
        .data(CMCUtils.OBJECT_MAPPER.writeValueAsString(Arrays.asList(
          CertificateData.builder()
            .certificate(testCert01.getEncoded())
            .valid(true)
            .build(),
          CertificateData.builder()
            .certificate(testCert02.getEncoded())
            .valid(true)
            .build(),
          CertificateData.builder()
            .certificate(testCert03.getEncoded())
            .valid(false)
            .revocationDate(System.currentTimeMillis())
            .revocationReason(0)
            .build()
        )))
        .build());
    cmcResponse = cmcResponseFactory.getCMCResponse(responseModel);
    log.info("CMC List cert response:\n{}", CMCDataPrint.printCMCResponse(cmcResponse, true));
    CMCDataValidator.validateCMCResponse(cmcResponse, responseModel);
    cmcParsed = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes());
    log.info("Parsed List cert response:\n{}", CMCDataPrint.printCMCResponse(cmcParsed, false));
    CMCDataValidator.validateCMCResponse(cmcParsed, responseModel);

    //List all serials
    responseModel = new CMCAdminResponseModel(nonce, TestResponseStatus.success.getResponseStatus(), processedObjects, AdminCMCData.builder()
        .adminRequestType(AdminRequestType.allCertSerials)
        .data(CMCUtils.OBJECT_MAPPER.writeValueAsString(Arrays.asList(
          BigInteger.ONE,BigInteger.TWO, BigInteger.TEN
        )))
        .build());
    cmcResponse = cmcResponseFactory.getCMCResponse(responseModel);
    log.info("CMC List all serials response:\n{}", CMCDataPrint.printCMCResponse(cmcResponse, true));
    CMCDataValidator.validateCMCResponse(cmcResponse, responseModel);
    cmcParsed = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes());
    log.info("Parsed List all serials response:\n{}", CMCDataPrint.printCMCResponse(cmcParsed, false));
    CMCDataValidator.validateCMCResponse(cmcParsed, responseModel);
  }

  private CMCRequestModel getCMCRequest(TestCAService ca, CertificateModel certificateModel, KeyPair kp, boolean crmf,
    CMCRequestFactory cmcRequestFactory)
    throws IOException {

    CMCRequestModel cmcRequestModel = crmf
      ? new CMCCertificateRequestModel(certificateModel, "profileCrmf")
      : new CMCCertificateRequestModel(certificateModel, "profilePkcs10",
      kp.getPrivate(), CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA256);
    return cmcRequestModel;
  }

}
