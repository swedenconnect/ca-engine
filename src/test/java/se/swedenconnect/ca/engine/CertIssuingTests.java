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

package se.swedenconnect.ca.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.utils.printcert.PrintCertificate;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;
import se.swedenconnect.ca.engine.components.BasicIssuerCAService;
import se.swedenconnect.ca.engine.components.CertRequestData;
import se.swedenconnect.ca.engine.components.CertValidatorComponents;
import se.swedenconnect.ca.engine.components.TestCAProvider;
import se.swedenconnect.ca.engine.components.TestUtils;
import se.swedenconnect.ca.engine.components.TestValidators;
import se.swedenconnect.ca.engine.data.TestCa;
import se.swedenconnect.ca.engine.data.TestData;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.cert.extensions.AuthnContext;
import se.swedenconnect.cert.extensions.OCSPNoCheck;
import se.swedenconnect.sigval.cert.chain.ExtendedCertPathValidatorException;
import se.swedenconnect.sigval.cert.chain.PathValidationResult;
import se.swedenconnect.sigval.cert.validity.ValidationStatus;
import se.swedenconnect.sigval.cert.validity.crl.CRLCache;
import se.swedenconnect.sigval.cert.validity.crl.impl.CRLValidityChecker;
import se.swedenconnect.sigval.cert.validity.ocsp.OCSPCertificateVerifier;

/**
 * Unit tests for the CA components lib
 *
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CertIssuingTests {

  /**
   * Initializes the CA services used to provide certificates and revocation services based on this library
   */
  @BeforeAll
  public static void init() {
    Security.addProvider(new BouncyCastleProvider());
    // Setup CA:s
    log.info("Setting up test CA:s");
    TestData.addCaAndValidator(TestCa.RSA_CA);
    TestData.addCaAndValidator(TestCa.RSA_PSS_CA);
    TestData.addCaAndValidator(TestCa.ECDSA_CA);
    TestData.addCaAndValidator(TestCa.RSA_EC_CA);
  }

  /**
   * Testing certificate path validation of certificates issued by test CA services
   *
   * @throws Exception errors
   */
  @Test
  public void certPathValidation() throws Exception {

    //Specify the tests being performed
    List<CATestInput> caTestList = Arrays.asList(
      new CATestInput(TestCa.RSA_CA, TestUtils.KeyType.EC, TestUtils.NistCurve.P521, true),
      new CATestInput(TestCa.RSA_PSS_CA, TestUtils.KeyType.EC, TestUtils.NistCurve.P256, false),
      new CATestInput(TestCa.ECDSA_CA, TestUtils.KeyType.EC, TestUtils.NistCurve.P384, true),
      new CATestInput(TestCa.ECDSA_CA, TestUtils.KeyType.RSA, 3072, false),
      new CATestInput(TestCa.RSA_EC_CA, TestUtils.KeyType.EC, TestUtils.NistCurve.P256, true),
      new CATestInput(TestCa.RSA_EC_CA, TestUtils.KeyType.RSA, 2048, false)
    );

    // Running all the test cases
    for (CATestInput input : caTestList) {
      CATestResult caTestResult = testCaProvider(input);
      // Validate the certificate path of the newly issued certificate
      PathValidationResult result = caTestResult.getResult();
      // Assert that validation was successful
      assertEquals(3, result.getValidatedCertificatePath().size());
      assertEquals(ValidationStatus.CertificateValidity.VALID, result.getValidationStatusList().get(0).getValidity());
      assertEquals(ValidationStatus.CertificateValidity.VALID, result.getValidationStatusList().get(1).getValidity());
      // Try to revoke the certificate
      BigInteger serialNumber = caTestResult.subjectCert.getSerialNumber();
      BasicIssuerCAService ca = caTestResult.getCaProvider().getCa();
      ca.revokeCertificate(serialNumber, 0, new Date());
      ca.publishNewCrl();
      // Now validate the revoked certificate
      PathValidationResult revokedResult = validateCert(serialNumber, input.getTestCa(), true);
      // Assert the expected results
      assertEquals(ValidationStatus.CertificateValidity.REVOKED, revokedResult.getValidationStatusList().get(0).getValidity());
      assertEquals(ValidationStatus.CertificateValidity.VALID, revokedResult.getValidationStatusList().get(1).getValidity());
      assertEquals(input.isIncludeCrlDp()
          ? ValidationStatus.ValidatorSourceType.CRL
          : ValidationStatus.ValidatorSourceType.OCSP,
        revokedResult.getValidationStatusList().get(0).getSourceType());
    }

  }

  private CATestResult testCaProvider(CATestInput input) throws Exception {
    TestCa testCa = input.getTestCa();
    TestCAProvider testCAProvider = TestData.getTestCAs().get(testCa);
    BasicIssuerCAService ca = testCAProvider.getCa();
    KeyPair kp = TestUtils.generateKeyPair(input.getKeyType(), input.getSpec());
    DefaultCertificateModelBuilder certificateModelBuilder = ca.getCertificateModelBuilder(
      CertRequestData.getTypicalSubejctName("Nisse", "Hult", "1234567890"), kp.getPublic());
    if (!input.includeCrlDp) {
      certificateModelBuilder.crlDistributionPoints(null);
    }
    X509CertificateHolder certificateHolder = ca.issueCertificate(certificateModelBuilder.build());
    ca.publishNewCrl();
    PathValidationResult validationResult = validateCert(certificateHolder.getSerialNumber(), testCa, false);

    return CATestResult.builder()
      .testCa(testCa)
      .caProvider(testCAProvider)
      .subjectCert(certificateHolder)
      .result(validationResult)
      .build();
  }

  private PathValidationResult validateCert(BigInteger certSerial, TestCa testCa, boolean recacheCrl) throws Exception {
    TestCAProvider testCAProvider = TestData.getTestCAs().get(testCa);
    BasicIssuerCAService ca = testCAProvider.getCa();
    CARepository caRepository = ca.getCaRepository();
    CertificateRecord certificate = caRepository.getCertificate(certSerial);
    CertValidatorComponents validatorComponents = TestData.getCertValidators().get(testCa);
    CRLCache crlCache = validatorComponents.getCrlCache();
    if (recacheCrl) {
      crlCache.recache();
    }
    CertificateValidator certificateValidator = validatorComponents.getCertificateValidator();
    try {
      PathValidationResult result = (PathValidationResult) certificateValidator.validate(
        TestUtils.getCertificate(certificate.getCertificate()),
        TestUtils.getChain(certificate.getCertificate(), testCa), null);
      return result;
    }
    catch (ExtendedCertPathValidatorException ex) {
      log.info("Path validation failed");
      return ex.getPathValidationResult();
    }
  }

  /**
   * Build and issue certificate using the certificate model builder
   *
   * @throws Exception
   */
  @Test
  public void certificateModelBuilderTest() throws Exception {
    TestCAProvider caProvider = TestData.getTestCAs().get(TestCa.ECDSA_CA);
    BasicIssuerCAService ca = caProvider.getCa();

    DefaultCertificateModelBuilder certModelBuilder = CertRequestData.getCompleteCertModelBuilder(
      TestData.ec256kp01.getPublic(), ca.getCaCertificate(), ca.getCertificateIssuer().getCertificateIssuerModel()
    );
    CertificateModel certificateModel = certModelBuilder.build();
    CertRequestData.addUncommonExtensions(certificateModel);

    X509CertificateHolder certificate = ca.issueCertificate(certificateModel);
    PrintCertificate printCertificate = new PrintCertificate(certificate);
    final String pemCert = printCertificate.toPEM();
    final String certPrint = printCertificate.toString(true, true, true);
    log.info("Complex certificate issue test - PEM:\n{}", pemCert);
    log.info("Complex certificate issue test - Content:\n{}", certPrint);

    //Test certificate content
    List<AttributeTypeAndValueModel> subjAttr = TestUtils.getAttributeValues(certificate.getSubject());
    assertEquals("SE", getVal(CertAttributes.C, subjAttr));
    assertEquals("Organization AB", getVal(CertAttributes.O, subjAttr));
    assertEquals("Dev department", getVal(CertAttributes.OU, subjAttr));
    assertEquals("196405065683", getVal(CertAttributes.SERIALNUMBER, subjAttr));
    assertEquals("Nisse", getVal(CertAttributes.GIVENNAME, subjAttr));
    assertEquals("Hult", getVal(CertAttributes.SURNAME, subjAttr));
    assertEquals("Nisse Hult", getVal(CertAttributes.CN, subjAttr));
    assertEquals("CEO", getVal(CertAttributes.T, subjAttr));
    assertEquals("nisse.hult@example.com", getVal(CertAttributes.EmailAddress, subjAttr));
    assertEquals("19640506", getVal(CertAttributes.DATE_OF_BIRTH, subjAttr));
    assertEquals("556778-1122", getVal(CertAttributes.ORGANIZATION_IDENTIFIER, subjAttr));
    assertEquals("example.com", getVal(CertAttributes.DC, subjAttr));

    List<AttributeTypeAndValueModel> issAttr = TestUtils.getAttributeValues(certificate.getIssuer());
    assertEquals("SE", getVal(CertAttributes.C, issAttr));
    assertEquals("Test Org", getVal(CertAttributes.O, issAttr));
    assertEquals("ECDSA Test CA", getVal(CertAttributes.CN, issAttr));

    // Check that all extensions are in included in the certificate
    Extensions extensions = certificate.getExtensions();
    assertNotNull(extensions.getExtension(Extension.basicConstraints));
    assertNotNull(extensions.getExtension(Extension.authorityKeyIdentifier));
    assertNotNull(extensions.getExtension(Extension.subjectKeyIdentifier));
    assertNotNull(extensions.getExtension(Extension.keyUsage));
    assertNotNull(extensions.getExtension(Extension.extendedKeyUsage));
    assertNotNull(extensions.getExtension(Extension.cRLDistributionPoints));
    assertNotNull(extensions.getExtension(Extension.authorityInfoAccess));
    assertNotNull(extensions.getExtension(Extension.subjectInfoAccess));
    assertNotNull(extensions.getExtension(Extension.certificatePolicies));
    assertNotNull(extensions.getExtension(AuthnContext.OID));
    assertNotNull(extensions.getExtension(Extension.qCStatements));
    assertNotNull(extensions.getExtension(Extension.subjectAlternativeName));
    assertNotNull(extensions.getExtension(Extension.subjectDirectoryAttributes));
    assertNotNull(extensions.getExtension(OCSPNoCheck.OID));
    assertNotNull(extensions.getExtension(Extension.issuerAlternativeName));
    assertNotNull(extensions.getExtension(Extension.inhibitAnyPolicy));
    assertNotNull(extensions.getExtension(Extension.nameConstraints));
    assertNotNull(extensions.getExtension(Extension.policyConstraints));
    assertNotNull(extensions.getExtension(Extension.policyMappings));
    assertNotNull(extensions.getExtension(Extension.privateKeyUsagePeriod));
  }

  private String getVal(ASN1ObjectIdentifier attrTpe, List<AttributeTypeAndValueModel> attributes) {
    Optional<String> valueOptional = attributes.stream()
      .filter(atavModel -> atavModel.getAttributeType().equals(attrTpe))
      .map(atavModel -> (String) atavModel.getValue())
      .findFirst();
    return valueOptional.orElse(null);
  }

  /**
   * Test revocation of individual certificates using the CRL and OCSP services
   *
   * @throws Exception
   */
  @Test
  public void revocationTest() throws Exception {
    TestCAProvider cap01 = TestData.getTestCAs().get(TestCa.ECDSA_CA);
    BasicIssuerCAService ca01 = cap01.getCa();
    X509CertificateHolder cert01 = issueCert(ca01);
    TestCAProvider cap02 = TestData.getTestCAs().get(TestCa.RSA_EC_CA);
    BasicIssuerCAService ca02 = cap02.getCa();
    X509CertificateHolder cert02 = issueCert(ca02);

    //Check OCSP
    checkOCSPValidation(getOcspVerifier(cert01, ca01.getCaCertificate(), ca01, true), ValidityResult.good);
    checkOCSPValidation(getOcspVerifier(cert01, ca01.getCaCertificate(), ca01, false), ValidityResult.good_noNonce);
    checkOCSPValidation(getOcspVerifier(cert01, ca01.getCaCertificate(), ca02, true), ValidityResult.malformedReq);
    checkOCSPValidation(getOcspVerifier(cert02, ca01.getCaCertificate(), ca01, true), ValidityResult.unknown);
    checkOCSPValidation(getOcspVerifier(cert02, ca02.getCaCertificate(), ca02, true), ValidityResult.good);
    checkOCSPValidation(getOcspVerifier(cert02, ca01.getCaCertificate(), ca02, true), ValidityResult.malformedReq);
    //Check CRL
    checkCRLValidation(getCRLVerifier(cert01, TestCa.ECDSA_CA), ValidityResult.good);
    checkCRLValidation(getCRLVerifier(cert02, TestCa.RSA_EC_CA), ValidityResult.good);

    // Revoke cert 01
    revokeCert(cert01, CRLReason.unspecified, TestCa.ECDSA_CA);
    checkOCSPValidation(getOcspVerifier(cert01, ca01.getCaCertificate(), ca01, true), ValidityResult.revoked);
    checkOCSPValidation(getOcspVerifier(cert01, ca01.getCaCertificate(), ca01, true), ValidityResult.good,
      new Date(System.currentTimeMillis() - 5000));
    checkCRLValidation(getCRLVerifier(cert01, TestCa.ECDSA_CA), ValidityResult.revoked);

    // Revoke cert 02
    revokeCert(cert02, CRLReason.certificateHold, TestCa.RSA_EC_CA);
    checkOCSPValidation(getOcspVerifier(cert02, ca02.getCaCertificate(), ca02, true), ValidityResult.onhold);
    checkCRLValidation(getCRLVerifier(cert02, TestCa.RSA_EC_CA), ValidityResult.onhold);
  }

  private void checkCRLValidation(CRLValidityChecker crlVerifier, ValidityResult expected) {
    ValidationStatus validationStatus = crlVerifier.checkValidity();
    ValidationStatus.CertificateValidity validity = validationStatus.getValidity();
    int reason = validationStatus.getReason();

    switch (expected) {
    case good:
      assertEquals(ValidationStatus.CertificateValidity.VALID, validity);
      break;
    case revoked:
      assertEquals(ValidationStatus.CertificateValidity.REVOKED, validity);
      assertEquals(CRLReason.unspecified, reason);
      break;
    case onhold:
      assertEquals(ValidationStatus.CertificateValidity.REVOKED, validity);
      assertEquals(CRLReason.certificateHold, reason);
      break;
    case malformedReq:
    case good_noNonce:
      throw new IllegalArgumentException("Illegal expected result");
    default:
      throw new IllegalArgumentException("Illegal expected result");
    }
  }

  private CRLValidityChecker getCRLVerifier(X509CertificateHolder cert01, TestCa caConf) throws IOException, CertificateException {
    CertValidatorComponents validatorComponents = TestData.getCertValidators().get(caConf);
    CRLCache crlCache = validatorComponents.getCrlCache();
    BasicIssuerCAService ca = TestData.getTestCAs().get(caConf).getCa();
    CRLValidityChecker crlValidityChecker = new CRLValidityChecker(
      TestUtils.getCertificate(cert01.getEncoded()),
      TestUtils.getCertificate(ca.getCaCertificate().getEncoded()), crlCache);
    return crlValidityChecker;
  }

  private void revokeCert(X509CertificateHolder cert, int reason, TestCa caConf) throws CertificateRevocationException {
    CertValidatorComponents validatorComponents = TestData.getCertValidators().get(caConf);
    BasicIssuerCAService ca = TestData.getTestCAs().get(caConf).getCa();
    ca.revokeCertificate(cert.getSerialNumber(), reason, new Date());
    ca.publishNewCrl();
    validatorComponents.getCrlCache().recache();
  }

  private void checkOCSPValidation(OCSPVerifierBundle ocspVerifierBundle, ValidityResult expected, Date time)
    throws IOException, OCSPException {
    OCSPCertificateVerifier ocspVerifier = ocspVerifierBundle.getOcspVerifier();
    TestValidators.TestOCSPDataLoader dataLoader = ocspVerifierBundle.getDataLoader();
    ValidationStatus validationStatus = ocspVerifier.checkValidity(time);
    byte[] responseBytes = Base64.decode(dataLoader.getLastResponseB64());

    OCSPResp ocspResp = new OCSPResp(responseBytes);
    int status = ocspResp.getStatus();
    BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
    Extension nonceExtension = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
    ValidationStatus.CertificateValidity validity = validationStatus.getValidity();
    int reason = validationStatus.getReason();

    switch (expected) {

    case good:
      assertEquals(OCSPResp.SUCCESSFUL, status);
      assertNotNull(nonceExtension);
      assertEquals(ValidationStatus.CertificateValidity.VALID, validity);
      break;
    case good_noNonce:
      assertEquals(OCSPResp.SUCCESSFUL, status);
      assertEquals(ValidationStatus.CertificateValidity.VALID, validity);
      assertNull(nonceExtension);
      break;
    case revoked:
      assertEquals(OCSPResp.SUCCESSFUL, status);
      assertEquals(ValidationStatus.CertificateValidity.REVOKED, validity);
      assertEquals(CRLReason.unspecified, reason);
      break;
    case malformedReq:
      assertEquals(OCSPResp.MALFORMED_REQUEST, status);
      break;
    case unknown:
      assertEquals(OCSPResp.SUCCESSFUL, status);
      assertEquals(ValidationStatus.CertificateValidity.UNKNOWN, validity);
      break;
    case onhold:
      assertEquals(OCSPResp.SUCCESSFUL, status);
      assertEquals(ValidationStatus.CertificateValidity.REVOKED, validity);
      assertEquals(CRLReason.certificateHold, reason);
      break;
    }
  }

  private void checkOCSPValidation(OCSPVerifierBundle ocspVerifierBundle, ValidityResult expected) throws IOException, OCSPException {
    checkOCSPValidation(ocspVerifierBundle, expected, new Date());
  }

  private X509CertificateHolder issueCert(BasicIssuerCAService ca) throws CertificateIssuanceException {
    DefaultCertificateModelBuilder certificateModelBuilder = ca.getCertificateModelBuilder(
      CertRequestData.getTypicalSubejctName("John", "Doe", "1234567890"),
      TestData.rsa2048kp01.getPublic());
    X509CertificateHolder certificate = ca.issueCertificate(certificateModelBuilder.build());
    return certificate;
  }

  private OCSPVerifierBundle getOcspVerifier(
    X509CertificateHolder cert, X509CertificateHolder issuer, BasicIssuerCAService ocspCa, boolean includeNonce) throws Exception {
    OCSPCertificateVerifier ocspCertVerifier = new OCSPCertificateVerifier(
      TestUtils.getCertificate(cert.getEncoded()),
      TestUtils.getCertificate(issuer.getEncoded()));
    TestValidators.TestOCSPDataLoader ocspDataLoader = new TestValidators.TestOCSPDataLoader(ocspCa);
    ocspDataLoader.setEnforceUrlMatch(false);
    ocspCertVerifier.setOcspDataLoader(ocspDataLoader);
    ocspCertVerifier.setIncludeNonce(includeNonce);
    return new OCSPVerifierBundle(ocspCertVerifier, ocspDataLoader);
  }

  private enum ValidityResult {
    good, good_noNonce, revoked, malformedReq, unknown, onhold;
  }

  @Data
  @AllArgsConstructor
  private class OCSPVerifierBundle {
    OCSPCertificateVerifier ocspVerifier;
    TestValidators.TestOCSPDataLoader dataLoader;
  }

  @Data
  @AllArgsConstructor
  private static class CATestInput {
    TestCa testCa;
    TestUtils.KeyType keyType;
    Object spec;
    boolean includeCrlDp;
  }

  @Data
  @Builder
  @AllArgsConstructor
  private static class CATestResult {
    TestCa testCa;
    TestCAProvider caProvider;
    X509CertificateHolder subjectCert;
    PathValidationResult result;
  }

}
