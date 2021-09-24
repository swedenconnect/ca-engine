package se.swedenconnect.ca.cmc;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.swedenconnect.ca.cmc.api.CMCRequest;
import se.swedenconnect.ca.cmc.auth.impl.DirectTrustCMCValidator;
import se.swedenconnect.ca.cmc.ca.*;
import se.swedenconnect.ca.cmc.model.CMCRequestModel;
import se.swedenconnect.ca.cmc.model.impl.CMCCertificateRequestModel;
import se.swedenconnect.ca.cmc.utils.CMCSigner;
import se.swedenconnect.ca.cmc.utils.TestUtils;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

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
    DefaultCertificateModelBuilder certificateModelBuilder = ca.getCertificateModelBuilder(new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value("Nisse Hult").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SERIALNUMBER).value("1234567890").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.GIVENNAME).value("Nisse").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SURNAME).value("Hult").build()
    )), subjectKeyPair.getPublic());
    CertificateModel certificateModel = certificateModelBuilder.build();

    CMCRequest cmcRequest;
    CMCRequest cmcParsed;
    //Create certificate request with PKCS#10
    cmcRequest = getCMCRequest(ca, certificateModel, subjectKeyPair, false);
    log.debug("Test logging");
    cmcParsed = new CMCRequest(cmcRequest.getCmcRequestBytes(), new DirectTrustCMCValidator(cmcSigner.getSignerChain().get(0)));

    //Create certificate request with CRMF
    cmcRequest = getCMCRequest(ca, certificateModel, subjectKeyPair, false);
    cmcParsed = new CMCRequest(cmcRequest.getCmcRequestBytes(), new DirectTrustCMCValidator(cmcSigner.getSignerChain().get(0)));


  }


  private CMCRequest getCMCRequest(TestCAService ca, CertificateModel certificateModel, KeyPair kp, boolean crmf)
    throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, OperatorCreationException, IOException, CRMFException,
    CertificateEncodingException {

    CMCRequestModel cmcRequestModel = crmf
      ? new CMCCertificateRequestModel(certificateModel, "profile1", cmcSigner.getContentSigner(), cmcSigner.getSignerChain())
      : new CMCCertificateRequestModel(certificateModel, "profile1", cmcSigner.getContentSigner(), cmcSigner.getSignerChain(),
      kp.getPrivate(), CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA256);
    CMCRequest cmcRequest = new CMCRequest(cmcRequestModel);
    return cmcRequest;
  }







}
