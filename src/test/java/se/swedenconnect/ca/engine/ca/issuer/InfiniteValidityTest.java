/*
 * Copyright 2021-2026 Sweden Connect
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
package se.swedenconnect.ca.engine.ca.issuer;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import se.swedenconnect.ca.engine.ca.issuer.impl.BasicCertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.impl.SelfIssuedCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.SelfIssuedCertificateModelBuilder;
import se.swedenconnect.ca.engine.components.CertRequestData;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the "infinite validity" feature: {@code Duration.ZERO} on the {@link CertificateIssuerModel} expiry offset
 * yields a certificate whose {@code notAfter} is the RFC 5280 §4.1.2.5 "no well-defined expiration date" value
 * ({@code 99991231235959Z}, encoded as ASN.1 GeneralizedTime), while {@code notBefore} is unaffected.
 */
class InfiniteValidityTest {

  private static final String ALGO = CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA256;

  private static KeyPair caKeyPair;
  private static KeyPair eeKeyPair;

  @BeforeAll
  static void init() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    caKeyPair = generateEcKeyPair();
    eeKeyPair = generateEcKeyPair();
  }

  // --- Pure logic: getOffsetTime -------------------------------------------------------------

  @Test
  void getOffsetTime_zeroWithInfiniteFlag_returnsNoExpiryValue() {
    assertEquals(Instant.parse("9999-12-31T23:59:59Z"), CertificateIssuer.INFINITE_EXPIRY);
    final Date notAfter = CertificateIssuer.getOffsetTime(Duration.ZERO, true);
    assertEquals(Date.from(CertificateIssuer.INFINITE_EXPIRY), notAfter);
  }

  @Test
  void getOffsetTime_zeroWithoutInfiniteFlag_isNow_notInfinite() {
    // This is the notBefore path: ZERO must NOT be treated as infinite here.
    final Instant result = CertificateIssuer.getOffsetTime(Duration.ZERO, false).toInstant();
    final Instant now = Instant.now();
    assertTrue(result.isAfter(now.minusSeconds(60)) && result.isBefore(now.plusSeconds(60)),
        "Duration.ZERO without the infinite flag must resolve to ~now, not the year 9999");
  }

  @Test
  void getOffsetTime_nonZeroWithFlag_isOffsetFromNow() {
    final Instant result = CertificateIssuer.getOffsetTime(Duration.ofDays(365), true).toInstant();
    final Instant now = Instant.now();
    assertTrue(result.isAfter(now) && result.isBefore(CertificateIssuer.INFINITE_EXPIRY),
        "A non-zero duration must be a normal offset from now, even with the infinite flag set");
  }

  // --- Model guards --------------------------------------------------------------------------

  @Test
  void model_setInfiniteValidity_semantics() throws Exception {
    final CertificateIssuerModel model = new CertificateIssuerModel(ALGO, Duration.ofDays(365));
    assertTrue(!model.isInfiniteValidity());
    model.setInfiniteValidity();
    assertTrue(model.isInfiniteValidity());
    assertEquals(Duration.ZERO, model.getExpiryOffset());
  }

  @Test
  void model_zeroExpiry_isRejectedOnEveryPath() {
    assertThrows(IllegalArgumentException.class, () -> new CertificateIssuerModel(ALGO, Duration.ZERO));
    assertThrows(IllegalArgumentException.class, () -> {
      final CertificateIssuerModel m = new CertificateIssuerModel(ALGO, Duration.ofDays(1));
      m.setExpiryOffset(Duration.ZERO);
    });
    assertThrows(NullPointerException.class, () -> {
      final CertificateIssuerModel m = new CertificateIssuerModel(ALGO, Duration.ofDays(1));
      m.setExpiryOffset(null);
    });
  }

  // --- End to end: issued certificates -------------------------------------------------------

  @Test
  void selfIssued_infiniteValidity_encodesGeneralizedTime() throws Exception {
    final X509CertificateHolder caCert = issueSelfSignedCa(true);
    assertInfiniteNotAfter(caCert);
    assertNotBeforeIsAroundNow(caCert);
  }

  @Test
  void basicIssuer_v3_infiniteValidity_encodesGeneralizedTime() throws Exception {
    final X509CertificateHolder eeCert = issueEndEntity(false /* v1 */);
    assertEquals(3, eeCert.toASN1Structure().getVersionNumber());
    assertInfiniteNotAfter(eeCert);
    assertNotBeforeIsAroundNow(eeCert);
  }

  @Test
  void basicIssuer_v1_infiniteValidity_encodesGeneralizedTime() throws Exception {
    final X509CertificateHolder eeCert = issueEndEntity(true /* v1 */);
    assertEquals(1, eeCert.toASN1Structure().getVersionNumber());
    assertInfiniteNotAfter(eeCert);
    assertNotBeforeIsAroundNow(eeCert);
  }

  // --- Helpers -------------------------------------------------------------------------------

  /** Issues a self-signed CA certificate, optionally with infinite validity. */
  private static X509CertificateHolder issueSelfSignedCa(final boolean infinite) throws Exception {
    final CertificateIssuerModel caModel = new CertificateIssuerModel(ALGO, Duration.ofDays(3650));
    if (infinite) {
      caModel.setInfiniteValidity();
    }
    final SelfIssuedCertificateIssuer caIssuer = new SelfIssuedCertificateIssuer(caModel);
    final CertNameModel<?> caName = CertRequestData.getTypicalSubejctName("Test", "CA", "1234567890");
    final CertificateModelBuilder builder = SelfIssuedCertificateModelBuilder.getInstance(caKeyPair, caModel)
        .subject(caName)
        .basicConstraints(new BasicConstraintsModel(true, true))
        .includeSki(true)
        .keyUsage(new KeyUsageModel(KeyUsage.keyCertSign + KeyUsage.cRLSign, true));
    return caIssuer.issueCertificate(builder.build());
  }

  /** Issues an end-entity certificate from an infinite-validity {@link BasicCertificateIssuer}. */
  private static X509CertificateHolder issueEndEntity(final boolean v1) throws Exception {
    final X509CertificateHolder caCert = issueSelfSignedCa(false);
    final PkiCredential caCredential = new BasicCredential(List.of(CAUtils.getCert(caCert)), caKeyPair.getPrivate());

    final CertificateIssuerModel eeModel = new CertificateIssuerModel(ALGO, Duration.ofDays(365));
    eeModel.setInfiniteValidity();
    eeModel.setV1(v1);

    final BasicCertificateIssuer issuer = new BasicCertificateIssuer(eeModel, caCredential);
    final CertificateModel model = CertificateModel.builder()
        .subject(CertRequestData.getTypicalSubejctName("John", "Doe", "1234567890"))
        .publicKey(eeKeyPair.getPublic())
        .extensionModels(List.of()) // empty -> V1 path taken only when the issuer model has v1=true
        .build();
    return issuer.issueCertificate(model);
  }

  private static void assertInfiniteNotAfter(final X509CertificateHolder holder) {
    assertTrue(holder.toASN1Structure().getEndDate().toASN1Primitive() instanceof ASN1GeneralizedTime,
        "notAfter must be encoded as ASN.1 GeneralizedTime");
    assertEquals(CertificateIssuer.INFINITE_EXPIRY, holder.getNotAfter().toInstant(),
        "notAfter must be the RFC 5280 no-expiry value 9999-12-31T23:59:59Z");
  }

  private static void assertNotBeforeIsAroundNow(final X509CertificateHolder holder) {
    final Instant notBefore = holder.getNotBefore().toInstant();
    final Instant now = Instant.now();
    assertTrue(notBefore.isAfter(now.minusSeconds(3600)) && notBefore.isBefore(now.plusSeconds(3600)),
        "notBefore must be around issuance time, never affected by infinite validity");
  }

  private static KeyPair generateEcKeyPair() throws Exception {
    final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
    generator.initialize(new ECGenParameterSpec("P-256"));
    return generator.generateKeyPair();
  }
}
