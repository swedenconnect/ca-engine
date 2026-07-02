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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.idsec.utils.printcert.PrintCertificate;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.impl.BasicCertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.impl.SelfIssuedCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.GenericExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.SelfIssuedCertificateModelBuilder;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.cert.extensions.SignedDocumentBinding;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Issues certificates compliant with {@code draft-ietf-lamps-one-signature-certs}: the signedDocumentBinding
 * extension, no revocation ({@code noRevAvail}), infinite validity, nonRepudiation key usage, and an AKI.
 * A range of bindingType identifiers is exercised. Each successfully issued certificate is logged in Base64.
 */
@Slf4j
class OneSignatureCertificateTest {

  private static final String ALGO = CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA256;

  /** id-ce-noRevAvail extension OID (2.5.29.56), per RFC 9608. */
  private static final ASN1ObjectIdentifier NO_REV_AVAIL = new ASN1ObjectIdentifier("2.5.29.56");

  /** A fixed 32-byte "hash of the data to be signed". */
  private static final byte[] DATA_TBS_HASH = new byte[] {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
      0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
  };

  private static final AlgorithmIdentifier SHA256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

  private static KeyPair caKeyPair;
  private static KeyPair eeKeyPair;
  private static X509CertificateHolder caCert;
  private static BasicCertificateIssuer issuer;

  @BeforeAll
  static void init() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    caKeyPair = generateEcKeyPair();
    eeKeyPair = generateEcKeyPair();

    // "Example Org CA" self-issued issuer certificate (finite validity - only the EE cert is infinite).
    final CertificateIssuerModel caModel = new CertificateIssuerModel(ALGO, Duration.ofDays(3650));
    final SelfIssuedCertificateIssuer caIssuer = new SelfIssuedCertificateIssuer(caModel);
    final CertificateModelBuilder caBuilder = SelfIssuedCertificateModelBuilder.getInstance(caKeyPair, caModel)
        .subject(name("Example Org CA"))
        .basicConstraints(new BasicConstraintsModel(true, true))
        .includeSki(true)
        .keyUsage(new KeyUsageModel(KeyUsage.keyCertSign + KeyUsage.cRLSign, true));
    caCert = caIssuer.issueCertificate(caBuilder.build());

    // Certificate issuer configured for infinite validity.
    final CertificateIssuerModel eeModel = new CertificateIssuerModel(ALGO, Duration.ofDays(365));
    eeModel.setInfiniteValidity();
    final PkiCredential caCredential = new BasicCredential(List.of(CAUtils.getCert(caCert)), caKeyPair.getPrivate());
    issuer = new BasicCertificateIssuer(eeModel, caCredential);
  }

  @Test
  void issueOneSignatureCertificates_variousBindingTypes() throws Exception {
    // null == default binding (bindingType field omitted); the rest are the registered identifiers.
    final List<String> bindingTypes = Arrays.asList(null, "cades", "xades", "jws", "cose");
    for (final String bindingType : bindingTypes) {
      final X509CertificateHolder cert = issueOneSignatureCert(bindingType);
      assertCompliant(cert, bindingType);
      PrintCertificate pc = new PrintCertificate(cert);
      log.info("One signature certificate (bindingType={}):\n{}\n{}",
          bindingType == null ? "<default>" : bindingType,
          pc.toString(true, true, true),
          pc.toPEM());
    }
  }

  private X509CertificateHolder issueOneSignatureCert(final String bindingType) throws Exception {
    final DefaultCertificateModelBuilder builder =
        DefaultCertificateModelBuilder.getInstance(eeKeyPair.getPublic(), caCert, issuer.getCertificateIssuerModel())
            .subject(johnDoe())
            .includeAki(true)
            .includeSki(true)
            .keyUsage(new KeyUsageModel(KeyUsage.nonRepudiation, true))
            .noRevAvail(true);

    final CertificateModel model = builder.build();
    // The signedDocumentBinding extension is not a first-class builder property, so add it directly.
    model.getExtensionModels().add(new GenericExtensionModel(
        SignedDocumentBinding.OID, new SignedDocumentBinding(DATA_TBS_HASH, SHA256, bindingType)));

    return issuer.issueCertificate(model);
  }

  private static void assertCompliant(final X509CertificateHolder cert, final String expectedBindingType)
      throws Exception {
    // Infinite validity -> notAfter is GeneralizedTime 99991231235959Z.
    assertTrue(cert.toASN1Structure().getEndDate().toASN1Primitive() instanceof ASN1GeneralizedTime,
        "notAfter must be GeneralizedTime");
    assertEquals(CertificateIssuer.INFINITE_EXPIRY, cert.getNotAfter().toInstant());

    // AKI present.
    assertNotNull(cert.getExtension(Extension.authorityKeyIdentifier), "AKI must be present");

    // Key usage == nonRepudiation only.
    final KeyUsage keyUsage = KeyUsage.getInstance(cert.getExtension(Extension.keyUsage).getParsedValue());
    assertTrue(keyUsage.hasUsages(KeyUsage.nonRepudiation), "nonRepudiation must be set");
    assertTrue(!keyUsage.hasUsages(KeyUsage.digitalSignature), "only nonRepudiation expected");

    // noRevAvail present.
    assertNotNull(cert.getExtension(NO_REV_AVAIL), "noRevAvail must be present");

    // signedDocumentBinding present and round-trips to the expected bindingType.
    final Extension sdbExt = cert.getExtension(SignedDocumentBinding.OID);
    assertNotNull(sdbExt, "signedDocumentBinding must be present");
    final SignedDocumentBinding sdb = SignedDocumentBinding.getInstance(sdbExt.getParsedValue());
    assertEquals(expectedBindingType, sdb.getBindingType());
    assertTrue(sdbExt.isCritical() == false, "signedDocumentBinding SHOULD be non-critical");
  }

  private static CertNameModel<?> johnDoe() {
    return name("John Doe");
  }

  private static CertNameModel<?> name(final String commonName) {
    return new ExplicitCertNameModel(Arrays.asList(
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.O).value("Example Org").build(),
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value(commonName).build()));
  }

  private static KeyPair generateEcKeyPair() throws Exception {
    final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
    generator.initialize(new ECGenParameterSpec("P-256"));
    return generator.generateKeyPair();
  }
}
