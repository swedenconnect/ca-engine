package se.swedenconnect.ca.cmc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.idsec.sigval.cert.chain.ExtendedCertPathValidatorException;
import se.idsec.sigval.cert.chain.PathValidationResult;
import se.swedenconnect.ca.cmc.api.*;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;
import se.swedenconnect.ca.cmc.api.impl.DefaultCMCCaApi;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.auth.CMCValidator;
import se.swedenconnect.ca.cmc.auth.impl.DefaultCMCValidator;
import se.swedenconnect.ca.cmc.ca.*;
import se.swedenconnect.ca.cmc.data.CMCRequestData;
import se.swedenconnect.ca.cmc.data.TestResponseStatus;
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
import se.swedenconnect.ca.cmc.model.response.impl.CMCAdminResponseModel;
import se.swedenconnect.ca.cmc.model.response.impl.CMCBasicCMCResponseModel;
import se.swedenconnect.ca.cmc.utils.CMCDataValidator;
import se.swedenconnect.ca.cmc.utils.CMCSigner;
import se.swedenconnect.ca.cmc.utils.CMCDataPrint;
import se.swedenconnect.ca.cmc.utils.TestUtils;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.SortBy;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;
import se.swedenconnect.ca.engine.utils.CAUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

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
      testCert02 = ca.issueCertificate(subj2CertModelBuilder.build());
      KeyPair subjectKeyPair3 = TestUtils.generateECKeyPair(TestUtils.NistCurve.P256);
      DefaultCertificateModelBuilder subj3CertModelBuilder = ca.getCertificateModelBuilder(
        CMCRequestData.subjectMap.get(CMCRequestData.USER3), subjectKeyPair3.getPublic());
      testCert03 = ca.issueCertificate(subj3CertModelBuilder.build());

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
    PublicKey caPublicKey = CAUtils.getCert(ca.getCaCertificate()).getPublicKey();

    CMCResponseFactory cmcResponseFactory = new CMCResponseFactory(cmcSigner.getSignerChain(), cmcSigner.getContentSigner());
    CMCResponseParser cmcResponseParser = new CMCResponseParser(new DefaultCMCValidator(cmcSigner.getSignerChain().get(0)), caPublicKey);

    CMCResponseModel responseModel;
    CMCResponse cmcResponse;
    CMCResponse cmcParsed;
    CMCRequestType cmcRequestType;

    byte[] nonce = new byte[128];
    RNG.nextBytes(nonce);
    List<BodyPartID> processedObjects = Arrays.asList(
      new BodyPartID(Long.valueOf("1134")),
      new BodyPartID(Long.valueOf("1234")),
      new BodyPartID(Long.valueOf("345"))
    );

    cmcRequestType = CMCRequestType.issueCert;
    responseModel = new CMCBasicCMCResponseModel(nonce, TestResponseStatus.success.withBodyParts(processedObjects), cmcRequestType,
      "profile".getBytes(StandardCharsets.UTF_8), Arrays.asList(testCert01));
    cmcResponse = cmcResponseFactory.getCMCResponse(responseModel);
    log.info("CMC Cert Issue Success response:\n{}", CMCDataPrint.printCMCResponse(cmcResponse, true));
    CMCDataValidator.validateCMCResponse(cmcResponse, responseModel);
    cmcParsed = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes(), cmcRequestType);
    log.info("Parsed CMC Cert Issue Success response:\n{}", CMCDataPrint.printCMCResponse(cmcParsed, false));
    CMCDataValidator.validateCMCResponse(cmcParsed, responseModel);

    cmcRequestType = CMCRequestType.issueCert;
    responseModel = new CMCBasicCMCResponseModel(nonce, TestResponseStatus.failBadRequest.withBodyParts(processedObjects), cmcRequestType, "profile".getBytes(
        StandardCharsets.UTF_8), new ArrayList<>());
    cmcResponse = cmcResponseFactory.getCMCResponse(responseModel);
    log.info("CMC Fail response:\n{}", CMCDataPrint.printCMCResponse(cmcResponse, true));
    CMCDataValidator.validateCMCResponse(cmcResponse, responseModel);
    cmcParsed = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes(), cmcRequestType);
    log.info("Parsed CMC Success response:\n{}", CMCDataPrint.printCMCResponse(cmcParsed, false));
    CMCDataValidator.validateCMCResponse(cmcParsed, responseModel);

    cmcRequestType = CMCRequestType.admin;
    responseModel = new CMCAdminResponseModel(nonce, TestResponseStatus.success.withBodyParts(processedObjects), cmcRequestType, AdminCMCData.builder()
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
    cmcParsed = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes(), cmcRequestType);
    log.info("Parsed CA info response:\n{}", CMCDataPrint.printCMCResponse(cmcParsed, false));
    CMCDataValidator.validateCMCResponse(cmcParsed, responseModel);

    cmcRequestType = CMCRequestType.admin;
    responseModel = new CMCAdminResponseModel(nonce, TestResponseStatus.success.withBodyParts(processedObjects), cmcRequestType, AdminCMCData.builder()
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
    cmcParsed = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes(), cmcRequestType);
    log.info("Parsed List cert response:\n{}", CMCDataPrint.printCMCResponse(cmcParsed, false));
    CMCDataValidator.validateCMCResponse(cmcParsed, responseModel);

    //List all serials
    cmcRequestType = CMCRequestType.admin;
    responseModel = new CMCAdminResponseModel(nonce, TestResponseStatus.success.withBodyParts(processedObjects), cmcRequestType, AdminCMCData.builder()
        .adminRequestType(AdminRequestType.allCertSerials)
        .data(CMCUtils.OBJECT_MAPPER.writeValueAsString(Arrays.asList(
          BigInteger.ONE,BigInteger.TWO, BigInteger.TEN
        )))
        .build());
    cmcResponse = cmcResponseFactory.getCMCResponse(responseModel);
    log.info("CMC List all serials response:\n{}", CMCDataPrint.printCMCResponse(cmcResponse, true));
    CMCDataValidator.validateCMCResponse(cmcResponse, responseModel);
    cmcParsed = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes(), cmcRequestType);
    log.info("Parsed List all serials response:\n{}", CMCDataPrint.printCMCResponse(cmcParsed, false));
    CMCDataValidator.validateCMCResponse(cmcParsed, responseModel);
  }

  @Test
  public void checkCMCCaApi() throws Exception {

    TestCAHolder caHolder = TestServices.getTestCAs().get(TestCA.INSTANCE1);
    TestCAService ca = caHolder.getCscaService();
    PublicKey caPublicKey = CAUtils.getCert(ca.getCaCertificate()).getPublicKey();
    CMCResponseFactory cmcResponseFactory = new CMCResponseFactory(cmcSigner.getSignerChain(), cmcSigner.getContentSigner());
    CMCRequestParser cmcRequestParser = new CMCRequestParser(new DefaultCMCValidator(cmcSigner.getSignerChain().get(0)));
    CMCRequestFactory cmcRequestFactory = new CMCRequestFactory(cmcSigner.getSignerChain(), cmcSigner.getContentSigner());
    CMCResponseParser cmcResponseParser = new CMCResponseParser(new DefaultCMCValidator(cmcSigner.getSignerChain().get(0)), caPublicKey);
    KeyPair subjectKeyPair = TestUtils.generateECKeyPair(TestUtils.NistCurve.P256);
    final CertValidatorComponents certValidator = TestServices.getValidator(ValidatorProfile.NORMAL, true);

    DefaultCertificateModelBuilder p10CertificateModelBuilder = ca.getCertificateModelBuilder(
      CMCRequestData.subjectMap.get(CMCRequestData.PKCS10_USER), subjectKeyPair.getPublic());
    CertificateModel p10CertificateModel = p10CertificateModelBuilder.build();
    DefaultCertificateModelBuilder crmfCertificateModelBuilder = ca.getCertificateModelBuilder(
      CMCRequestData.subjectMap.get(CMCRequestData.CRMF_USER), subjectKeyPair.getPublic());
    CertificateModel crmfCertificateModel = crmfCertificateModelBuilder.build();

    CMCCaApi cmcCaApi = new DefaultCMCCaApi(ca, cmcRequestParser, cmcResponseFactory);

    CMCRequest cmcRequest;
    CMCRequestModel requestModel;
    CMCResponse cmcResponse;
    CMCResponse parsedCMCResponse;

    // Issue cert with PKCS#10
    requestModel = getCMCRequest(ca, p10CertificateModel, subjectKeyPair, false, cmcRequestFactory);
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC API Certificate request with PKCS#10:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcResponse = cmcCaApi.processRequest(cmcRequest);
    parsedCMCResponse = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes(), requestModel.getCmcRequestType());
    log.info("CMC response from API Certificate request with PKCS#10:\n{}", CMCDataPrint.printCMCResponse(parsedCMCResponse, true));
    Assertions.assertTrue(cmcResponse.getResponseStatus().getStatus().equals(CMCStatusType.success));
    Assertions.assertTrue(cmcResponse.getReturnCertificates().size() == 1);
    Assertions.assertTrue(parsedCMCResponse.getResponseStatus().getStatus().equals(CMCStatusType.success));
    Assertions.assertTrue(parsedCMCResponse.getReturnCertificates().size() == 1);
    final X509Certificate p10Cert = cmcResponse.getReturnCertificates().get(0);


    // Issue Cert with CRMF
    requestModel = getCMCRequest(ca, crmfCertificateModel, subjectKeyPair, true, cmcRequestFactory);
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC API Certificate request with CRMF:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcResponse = cmcCaApi.processRequest(cmcRequest);
    parsedCMCResponse = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes(), requestModel.getCmcRequestType());
    log.info("CMC response from API Certificate request with CRMF:\n{}", CMCDataPrint.printCMCResponse(parsedCMCResponse, true));
    Assertions.assertTrue(cmcResponse.getResponseStatus().getStatus().equals(CMCStatusType.success));
    Assertions.assertTrue(cmcResponse.getReturnCertificates().size() == 1);
    Assertions.assertTrue(parsedCMCResponse.getResponseStatus().getStatus().equals(CMCStatusType.success));
    Assertions.assertTrue(parsedCMCResponse.getReturnCertificates().size() == 1);
    final X509Certificate crmfCert = cmcResponse.getReturnCertificates().get(0);

    // Revoke certificate
    requestModel = new CMCRevokeRequestModel(crmfCert.getSerialNumber(), CRLReason.keyCompromise, new Date(), ca.getCaCertificate().getIssuer());
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC API Certificate Revocation:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    checkCertStatus(certValidator, crmfCert, true);
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcResponse = cmcCaApi.processRequest(cmcRequest);
    parsedCMCResponse = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes(), requestModel.getCmcRequestType());
    log.info("CMC response from API Certificate Revocation:\n{}", CMCDataPrint.printCMCResponse(parsedCMCResponse, true));
    checkCertStatus(certValidator, crmfCert, false);

    // Revoke non-existant cert with serial number 1
    requestModel = new CMCRevokeRequestModel(BigInteger.ONE, CRLReason.unspecified, new Date(), ca.getCaCertificate().getIssuer());
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC API Certificate Revocation of unknown serial number:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, false));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcResponse = cmcCaApi.processRequest(cmcRequest);
    parsedCMCResponse = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes(), requestModel.getCmcRequestType());
    log.info("CMC response from API Certificate Revocation of unknown serial number:\n{}", CMCDataPrint.printCMCResponse(parsedCMCResponse, true));
    Assertions.assertTrue(cmcResponse.getResponseStatus().getStatus().equals(CMCStatusType.failed));
    Assertions.assertTrue(cmcResponse.getResponseStatus().getFailType().equals(CMCFailType.badCertId));
    Assertions.assertTrue(parsedCMCResponse.getResponseStatus().getStatus().equals(CMCStatusType.failed));
    Assertions.assertTrue(parsedCMCResponse.getResponseStatus().getFailType().equals(CMCFailType.badCertId));


    // Get Cert
    requestModel = new CMCGetCertRequestModel(crmfCert.getSerialNumber(), ca.getCaCertificate().getSubject());
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC API Get Certificate:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcResponse = cmcCaApi.processRequest(cmcRequest);
    X509Certificate getCertCertificate = cmcResponse.getReturnCertificates().get(0);
    Assertions.assertEquals(crmfCert, getCertCertificate);
    parsedCMCResponse = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes(), requestModel.getCmcRequestType());
    log.info("CMC response from API Get Certificate:\n{}", CMCDataPrint.printCMCResponse(parsedCMCResponse, true));
    Assertions.assertTrue(cmcResponse.getResponseStatus().getStatus().equals(CMCStatusType.success));
    Assertions.assertTrue(cmcResponse.getReturnCertificates().size() == 1);
    Assertions.assertEquals(crmfCert, cmcResponse.getReturnCertificates().get(0));
    Assertions.assertTrue(parsedCMCResponse.getResponseStatus().getStatus().equals(CMCStatusType.success));
    Assertions.assertTrue(parsedCMCResponse.getReturnCertificates().size() == 1);
    Assertions.assertEquals(crmfCert, parsedCMCResponse.getReturnCertificates().get(0));

    // CAInfo
    requestModel = new CMCAdminRequestModel(AdminCMCData.builder().adminRequestType(AdminRequestType.caInfo).build());
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC API CA Info:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcResponse = cmcCaApi.processRequest(cmcRequest);
    parsedCMCResponse = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes(), requestModel.getCmcRequestType());
    log.info("CMC response from API Get Certificate:\n{}", CMCDataPrint.printCMCResponse(parsedCMCResponse, true));
    CAInformation caInformation = TestUtils.getCAInformation(cmcResponse);
    Assertions.assertEquals(5, caInformation.getCertificateCount());
    Assertions.assertEquals(4, caInformation.getValidCertificateCount());
    Assertions.assertArrayEquals(ca.getOCSPResponderCertificate().getEncoded(), caInformation.getOcspCertificate());
    Assertions.assertEquals(1, caInformation.getCertificateChain().size());
    Assertions.assertArrayEquals(ca.getCaCertificate().getEncoded(), caInformation.getCertificateChain().get(0));

    // List cert serials
    requestModel = new CMCAdminRequestModel(AdminCMCData.builder().adminRequestType(AdminRequestType.allCertSerials).build());
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC API List cert serials:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcResponse = cmcCaApi.processRequest(cmcRequest);
    parsedCMCResponse = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes(), requestModel.getCmcRequestType());
    log.info("CMC response from API List cert serials:\n{}", CMCDataPrint.printCMCResponse(parsedCMCResponse, true));
    final List<BigInteger> allSerials = TestUtils.getAllSerials(cmcResponse);
    Assertions.assertEquals(5, allSerials.size());
    Assertions.assertTrue(allSerials.contains(testCert01.getSerialNumber()));
    Assertions.assertTrue(allSerials.contains(testCert02.getSerialNumber()));
    Assertions.assertTrue(allSerials.contains(testCert03.getSerialNumber()));
    Assertions.assertTrue(allSerials.contains(p10Cert.getSerialNumber()));
    Assertions.assertTrue(allSerials.contains(crmfCert.getSerialNumber()));

    //Get all certs
    AdminCMCData adminData = (AdminCMCData) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_responseInfo, CMCUtils.getResponseControlSequence(cmcResponse.getPkiResponse())).getValue();
    List<String> serialHexStrList = CMCUtils.OBJECT_MAPPER.readValue(adminData.getData(), new TypeReference<List<String>>() {});
    log.info("Getting all certificates for all serial numbers {}", String.join(", ", serialHexStrList));
    for (BigInteger certSerial : allSerials) {
      requestModel = new CMCGetCertRequestModel(certSerial, ca.getCaCertificate().getSubject());
      cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
      cmcResponse = cmcCaApi.processRequest(cmcRequest);
      X509Certificate cert = cmcResponse.getReturnCertificates().get(0);
      log.info("Certificate issued to: {}", cert.getSubjectX500Principal());
      try {
        certValidator.getCertificateValidator().validate(cert, null);
        log.info("Certificate is valid");
        Assertions.assertNotEquals(crmfCert.getSerialNumber(), certSerial);
      } catch (Exception ex){
        log.info("Certificate is invalid/revoked");
        Assertions.assertEquals(crmfCert.getSerialNumber(), certSerial);
      }
    }

    // List certs
    requestModel = new CMCAdminRequestModel(AdminCMCData.builder().adminRequestType(AdminRequestType.listCerts)
      .data(CMCUtils.OBJECT_MAPPER.writeValueAsString(ListCerts.builder()
          .pageIndex(1)
          .pageSize(3)
          .valid(true)
          .sortBy(SortBy.issueDate)
        .build()))
      .build());
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC API List 2nd page valid certs:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcResponse = cmcCaApi.processRequest(cmcRequest);
    parsedCMCResponse = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes(), requestModel.getCmcRequestType());
    log.info("CMC response from API List 2nd page valid certs:\n{}", CMCDataPrint.printCMCResponse(parsedCMCResponse, true));
    List<CertificateData> certList = TestUtils.getCertList(cmcResponse);
    Assertions.assertEquals(1, certList.size());
    Assertions.assertArrayEquals(p10Cert.getEncoded(), certList.get(0).getCertificate());
    Assertions.assertEquals(true, certList.get(0).isValid());



    // List certs
    requestModel = new CMCAdminRequestModel(AdminCMCData.builder().adminRequestType(AdminRequestType.listCerts)
      .data(CMCUtils.OBJECT_MAPPER.writeValueAsString(ListCerts.builder()
          .pageIndex(1)
          .pageSize(3)
          .valid(false)
          .sortBy(SortBy.issueDate)
        .build()))
      .build());
    cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);
    log.info("CMC API List 2nd page all certs:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    CMCDataValidator.validateCMCRequest(cmcRequest, requestModel);
    cmcResponse = cmcCaApi.processRequest(cmcRequest);
    parsedCMCResponse = cmcResponseParser.parseCMCresponse(cmcResponse.getCmcResponseBytes(), requestModel.getCmcRequestType());
    log.info("CMC response from API List 2nd page valid certs:\n{}", CMCDataPrint.printCMCResponse(parsedCMCResponse, true));
    certList = TestUtils.getCertList(cmcResponse);
    Assertions.assertEquals(2, certList.size());
    Assertions.assertArrayEquals(crmfCert.getEncoded(), certList.get(1).getCertificate());
    Assertions.assertEquals(false, certList.get(1).isValid());

  }


  private void checkCertStatus(CertValidatorComponents certValidator, X509Certificate targetCert, boolean expValid) throws Exception{
    log.info("Validating certificate: {}", targetCert.getSubjectX500Principal());
    try {
      final PathValidationResult result = certValidator.getCertificateValidator().validate(targetCert, null);
      log.info("Certificate was valid");
      if (!expValid) {
        throw new IOException("Certificate was expected to be revoked, but was valid");
      }
    }
    catch (ExtendedCertPathValidatorException ex) {
      log.info("Certificate validation error: {}", ex.getMessage());
      if (expValid) {
        throw new IOException("Certificate was expected to be valid, but was revoked");
      }
    }
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
