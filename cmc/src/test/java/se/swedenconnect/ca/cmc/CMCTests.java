package se.swedenconnect.ca.cmc;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.swedenconnect.ca.cmc.api.CMCRequest;
import se.swedenconnect.ca.cmc.auth.impl.DirectTrustCMCValidator;
import se.swedenconnect.ca.cmc.ca.*;
import se.swedenconnect.ca.cmc.data.CMCRequestData;
import se.swedenconnect.ca.cmc.model.request.CMCRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCAdminRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCCertificateRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCGetCertRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCRevokeRequestModel;
import se.swedenconnect.ca.cmc.utils.CMCSigner;
import se.swedenconnect.ca.cmc.utils.CMCDataPrint;
import se.swedenconnect.ca.cmc.utils.TestUtils;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.util.Date;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMCTests {

  private static CMCSigner cmcSigner;
  private static final ObjectMapper objectMapper = new ObjectMapper();


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

    DefaultCertificateModelBuilder certificateModelBuilder = ca.getCertificateModelBuilder(CMCRequestData.subjectMap.get(CMCRequestData.DEFAULT), subjectKeyPair.getPublic());
    CertificateModel certificateModel = certificateModelBuilder.build();
    X509CertificateHolder testCert01 = ca.issueCertificate(certificateModel);

    CMCRequest cmcRequest;
    CMCRequest cmcParsed;
    //Create certificate request with PKCS#10
    cmcRequest = getCMCRequest(ca, certificateModel, subjectKeyPair, false);
    log.info("CMC Certificate request with PKCS#10:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    cmcParsed = new CMCRequest(cmcRequest.getCmcRequestBytes(), new DirectTrustCMCValidator(cmcSigner.getSignerChain().get(0)));
    log.info("Parsed CMC Certificate request with PKCS#10:\n{}", CMCDataPrint.printCMCRequest(cmcParsed, false, false));

    //Create certificate request with CRMF
    cmcRequest = getCMCRequest(ca, certificateModel, subjectKeyPair, true);
    log.info("CMC Certificate request with CRMF:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    cmcParsed = new CMCRequest(cmcRequest.getCmcRequestBytes(), new DirectTrustCMCValidator(cmcSigner.getSignerChain().get(0)));
    log.info("Parsed CMC Certificate request with CRMF:\n{}", CMCDataPrint.printCMCRequest(cmcParsed, false, false));


    //Create CMC revoke request
    BigInteger certSerial = testCert01.getSerialNumber();
    cmcRequest = new CMCRequest(new CMCRevokeRequestModel(
      certSerial, CRLReason.unspecified, new Date(),ca.getCaCertificate().getSubject(),
      cmcSigner.getContentSigner(), cmcSigner.getSignerChain()));
    log.info("CMC Revoke request:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    cmcParsed = new CMCRequest(cmcRequest.getCmcRequestBytes(), new DirectTrustCMCValidator(cmcSigner.getSignerChain().get(0)));
    log.info("Parsed CMC Revoke request:\n{}", CMCDataPrint.printCMCRequest(cmcParsed, false, false));

    //Create CMC Get Cert request
    cmcRequest = new CMCRequest(new CMCGetCertRequestModel(certSerial, ca.getCaCertificate().getSubject(),
      cmcSigner.getContentSigner(), cmcSigner.getSignerChain()));
    log.info("CMC Get Cert request:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    cmcParsed = new CMCRequest(cmcRequest.getCmcRequestBytes(), new DirectTrustCMCValidator(cmcSigner.getSignerChain().get(0)));
    log.info("Parsed CMC Get Cert request:\n{}", CMCDataPrint.printCMCRequest(cmcParsed, false, false));

    //Create CMC Admin request - CA Info
    cmcRequest = new CMCRequest(new CMCAdminRequestModel(CMCRequestData.adminRequestMap.get(CMCRequestData.CA_INFO),cmcSigner.getContentSigner(), cmcSigner.getSignerChain()));
    log.info("CMC Admin request - CA Info:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    cmcParsed = new CMCRequest(cmcRequest.getCmcRequestBytes(), new DirectTrustCMCValidator(cmcSigner.getSignerChain().get(0)));
    log.info("Parsed Admin request - CA Info:\n{}", CMCDataPrint.printCMCRequest(cmcParsed, false, false));

    //Create CMC Admin request - list certs
    cmcRequest = new CMCRequest(new CMCAdminRequestModel(CMCRequestData.adminRequestMap.get(CMCRequestData.LIST_CERTS),cmcSigner.getContentSigner(), cmcSigner.getSignerChain()));
    log.info("CMC Admin request - List Certs:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    cmcParsed = new CMCRequest(cmcRequest.getCmcRequestBytes(), new DirectTrustCMCValidator(cmcSigner.getSignerChain().get(0)));
    log.info("Parsed Admin request - List Certs:\n{}", CMCDataPrint.printCMCRequest(cmcParsed, false, false));

    //Create CMC Admin request - list all serials
    cmcRequest = new CMCRequest(new CMCAdminRequestModel(CMCRequestData.adminRequestMap.get(CMCRequestData.LIST_CERT_SERIALS),cmcSigner.getContentSigner(), cmcSigner.getSignerChain()));
    log.info("CMC Admin request - List All Serials:\n{}", CMCDataPrint.printCMCRequest(cmcRequest, true, true));
    cmcParsed = new CMCRequest(cmcRequest.getCmcRequestBytes(), new DirectTrustCMCValidator(cmcSigner.getSignerChain().get(0)));
    log.info("Parsed Admin request - List All Serials:\n{}", CMCDataPrint.printCMCRequest(cmcParsed, false, false));

  }


  private CMCRequest getCMCRequest(TestCAService ca, CertificateModel certificateModel, KeyPair kp, boolean crmf)
    throws IOException {

    CMCRequestModel cmcRequestModel = crmf
      ? new CMCCertificateRequestModel(certificateModel, "profileCrmf", cmcSigner.getContentSigner(), cmcSigner.getSignerChain())
      : new CMCCertificateRequestModel(certificateModel, "profilePkcs10", cmcSigner.getContentSigner(), cmcSigner.getSignerChain(),
      kp.getPrivate(), CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA256);
    CMCRequest cmcRequest = new CMCRequest(cmcRequestModel);
    return cmcRequest;
  }







}
