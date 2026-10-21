/*
 * Copyright 2026 Sweden Connect
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import lombok.extern.slf4j.Slf4j;
import se.idsec.utils.printcert.PrintCertificate;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.impl.BasicCertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.impl.SelfIssuedCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.data.AttributeMappingBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.data.OIDCAuthContextBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.data.SAMLAuthContextBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.SelfIssuedCertificateModelBuilder;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.cert.extensions.AuthnContext;
import se.swedenconnect.cert.extensions.SignedDocumentBinding;
import se.swedenconnect.cert.extensions.data.oaci.ClaimMapping;
import se.swedenconnect.cert.extensions.data.oaci.OIDCAuthContext;
import se.swedenconnect.cert.extensions.data.ProtocolAuthContext;
import se.swedenconnect.cert.extensions.data.saci.AttributeMapping;
import se.swedenconnect.cert.extensions.data.saci.SAMLAuthContext;
import se.swedenconnect.cert.extensions.utils.DOMUtils;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Issues minimal end-entity certificates carrying an Authentication Context extension (RFC 7773), one with SAML
 * Authentication Context Information (SACI, RFC 7773 Section 3) and one with OpenID Connect Authentication Context
 * Information (OACI, {@code draft-santesson-oidc-cert-auth-context}), suitable as examples for those specifications:
 * ordinary one-year validity, a CRL distribution point, nonRepudiation key usage, AKI/SKI, and no signedDocumentBinding
 * or noRevAvail extension. For each context type a minimal variant and a variant using every option of the
 * respective specification is issued. Each certificate is logged in printed and PEM form.
 */
@Slf4j
class AuthContextCertificateTest {

  private static final String ALGO = CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA256;

  /** id-ce-noRevAvail extension OID (2.5.29.56), per RFC 9608. */
  private static final ASN1ObjectIdentifier NO_REV_AVAIL = new ASN1ObjectIdentifier("2.5.29.56");

  private static final String CRL_DP_URL = "http://example.com/crl/example-org-ca.crl";

  /** Namespace of the Sweden Connect Extended Authentication Information element for SACI */
  private static final String SACEX_NS = "http://id.swedenconnect.se/auth-cont/1.0/ext-auth-info";

  /** SAML attribute name format used in the examples */
  private static final String URI_NAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

  /** Transaction identifier attribute of the Swedish eID Framework, used as extended authentication information */
  private static final String TRANSACTION_ID_ATTRIBUTE = "urn:oid:1.2.752.201.3.2";
  private static final String TRANSACTION_ID = "dc6ac7656H89bfb51";

  /** Fixed authentication time, 2026-10-19T13:04:05Z, so that the example is reproducible. */
  private static final Instant AUTH_TIME = Instant.ofEpochSecond(1792415045L);

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

    // "Example Org CA" self-issued issuer certificate.
    final CertificateIssuerModel caModel = new CertificateIssuerModel(ALGO, Duration.ofDays(3650));
    final SelfIssuedCertificateIssuer caIssuer = new SelfIssuedCertificateIssuer(caModel);
    final CertificateModelBuilder caBuilder = SelfIssuedCertificateModelBuilder.getInstance(caKeyPair, caModel)
        .subject(name("Example Org CA"))
        .basicConstraints(new BasicConstraintsModel(true, true))
        .includeSki(true)
        .keyUsage(new KeyUsageModel(KeyUsage.keyCertSign + KeyUsage.cRLSign, true));
    caCert = caIssuer.issueCertificate(caBuilder.build());

    // End-entity certificate issuer with an ordinary one-year validity period.
    final CertificateIssuerModel eeModel = new CertificateIssuerModel(ALGO, Duration.ofDays(365));
    final PkiCredential caCredential = new BasicCredential(List.of(CAUtils.getCert(caCert)), caKeyPair.getPrivate());
    issuer = new BasicCertificateIssuer(eeModel, caCredential);
  }

  @Test
  void issueMinimalSamlAuthContextCertificate() throws Exception {
    final SAMLAuthContext saci = exampleSamlAuthContext();
    final X509CertificateHolder cert = issueCertificate(saci, "SAML Authentication Context Information (SACI)");

    final AuthnContext authnContext = assertAuthContextCertificate(cert, AuthnContext.SACI_CONTEXT_TYPE);
    assertTrue(authnContext.getOidcAuthContexts().isEmpty());
    final SAMLAuthContext parsed = authnContext.getSamlAuthContexts().get(0);
    assertEquals(saci.getAuthContextInfo().getIdentityProvider(), parsed.getAuthContextInfo().getIdentityProvider());
    assertEquals(saci.getAuthContextInfo().getAuthnContextClassRef(),
        parsed.getAuthContextInfo().getAuthnContextClassRef());
    assertEquals(saci.getAuthContextInfo().getAssertionRef(), parsed.getAuthContextInfo().getAssertionRef());
    assertEquals(saci.getAuthContextInfo().getServiceID(), parsed.getAuthContextInfo().getServiceID());
    assertEquals(5, parsed.getIdAttributes().getAttributeMappings().size());
  }

  @Test
  void issueMinimalOidcAuthContextCertificate() throws Exception {
    final OIDCAuthContext oaci = exampleOidcAuthContext();
    final X509CertificateHolder cert = issueCertificate(oaci, "OpenID Connect Authentication Context Information (OACI)");

    final AuthnContext authnContext = assertAuthContextCertificate(cert, AuthnContext.OACI_CONTEXT_TYPE);
    assertTrue(authnContext.getSamlAuthContexts().isEmpty());
    assertEquals(oaci, authnContext.getOidcAuthContexts().get(0));
  }

  @Test
  void issueFullSamlAuthContextCertificate() throws Exception {
    final SAMLAuthContext saci = fullSamlAuthContext();
    final X509CertificateHolder cert = issueCertificate(saci, "SAML Authentication Context Information (SACI), all options");

    final AuthnContext authnContext = assertAuthContextCertificate(cert, AuthnContext.SACI_CONTEXT_TYPE);
    final SAMLAuthContext parsed = authnContext.getSamlAuthContexts().get(0);

    // Attribute mappings carry the attribute values
    final List<AttributeMapping> mappings = parsed.getIdAttributes().getAttributeMappings();
    assertEquals(5, mappings.size());
    assertEquals("198001011234", mappings.get(0).getAttribute().getAttributeValues().get(0).getTextContent());
    assertEquals("john.doe@example.com", mappings.get(4).getAttribute().getAttributeValues().get(0).getTextContent());

    // Extended authentication information: two ExtAuthInfo elements in the AuthContextInfo any-list
    final List<Element> extAuthInfo = parsed.getAuthContextInfo().getAnyList();
    assertNotNull(extAuthInfo);
    assertEquals(2, extAuthInfo.size());
    assertEquals(SACEX_NS, extAuthInfo.get(0).getNamespaceURI());
    assertEquals("ExtAuthInfo", extAuthInfo.get(0).getLocalName());
    assertEquals(TRANSACTION_ID_ATTRIBUTE, extAuthInfo.get(0).getAttribute("Name"));
    assertEquals(TRANSACTION_ID, extAuthInfo.get(0).getTextContent());
    assertEquals("https://example.com/attributes/sign-message-digest", extAuthInfo.get(1).getAttribute("Name"));
  }

  @Test
  void issueFullOidcAuthContextCertificate() throws Exception {
    final OIDCAuthContext oaci = fullOidcAuthContext();
    final X509CertificateHolder cert = issueCertificate(oaci,
        "OpenID Connect Authentication Context Information (OACI), all options");

    final AuthnContext authnContext = assertAuthContextCertificate(cert, AuthnContext.OACI_CONTEXT_TYPE);
    final OIDCAuthContext parsed = authnContext.getOidcAuthContexts().get(0);
    assertEquals(oaci, parsed);
    assertEquals(List.of("sc", "pin"), parsed.getAmr());
    assertEquals("a1b2c3d4e5f60718293a4b5c6d7e8f90", parsed.getSub());
    assertEquals(2, parsed.getAdditionalMembers().size());
    assertEquals(TRANSACTION_ID,
        parsed.getAdditionalMembers().get("https://example.com/claims/transaction_id").asString());
    assertEquals(ClaimMapping.Source.userinfo, parsed.getClaimMappings().get(4).getSource());
  }

  /**
   * Issues the minimal certificate with the given authentication context and logs it in printed and PEM form.
   */
  private static X509CertificateHolder issueCertificate(final ProtocolAuthContext authContext, final String label)
      throws Exception {
    final DefaultCertificateModelBuilder builder =
        DefaultCertificateModelBuilder.getInstance(eeKeyPair.getPublic(), caCert, issuer.getCertificateIssuerModel())
            .subject(johnDoe())
            .includeAki(true)
            .includeSki(true)
            .keyUsage(new KeyUsageModel(KeyUsage.nonRepudiation, true))
            .crlDistributionPoints(Collections.singletonList(CRL_DP_URL))
            .subjectAltNames(Collections.singletonMap(GeneralName.rfc822Name, "john.doe@example.com"))
            .authenticationContext(authContext);

    final X509CertificateHolder cert = issuer.issueCertificate(builder.build());
    final PrintCertificate pc = new PrintCertificate(cert);
    log.info("Minimal certificate with {}:\n{}\n{}", label, pc.toString(true, true, true), pc.toPEM());
    return cert;
  }

  /**
   * Asserts the properties common to both variants and returns the strictly parsed Authentication Context extension.
   */
  private static AuthnContext assertAuthContextCertificate(final X509CertificateHolder cert,
      final String expectedContextType) throws Exception {
    // Authentication Context extension: non-critical, exactly one entry of the expected type, strict parse
    final Extension authnContextExt = cert.getExtension(AuthnContext.OID);
    assertNotNull(authnContextExt, "Authentication Context extension must be present");
    assertFalse(authnContextExt.isCritical(), "Authentication Context extension must not be critical");
    final AuthnContext authnContext = AuthnContext.getInstance(authnContextExt.getParsedValue());
    assertEquals(1, authnContext.getEntries().size());
    assertEquals(expectedContextType, authnContext.getEntries().get(0).getContextType());

    // Ordinary validity (about one year) and revocation support through a CRL distribution point
    final Instant notAfter = cert.getNotAfter().toInstant();
    assertTrue(notAfter.isBefore(Instant.now().plus(366, ChronoUnit.DAYS)), "notAfter must be about one year ahead");
    assertTrue(notAfter.isAfter(Instant.now().plus(364, ChronoUnit.DAYS)), "notAfter must be about one year ahead");
    final Extension crlDpExt = cert.getExtension(Extension.cRLDistributionPoints);
    assertNotNull(crlDpExt, "CRL distribution point must be present");
    final DistributionPoint dp = CRLDistPoint.getInstance(crlDpExt.getParsedValue()).getDistributionPoints()[0];
    final GeneralNames dpFullName = GeneralNames.getInstance(dp.getDistributionPoint().getName());
    assertEquals(CRL_DP_URL, dpFullName.getNames()[0].getName().toString());

    // Key usage == nonRepudiation only, AKI present
    final KeyUsage keyUsage = KeyUsage.getInstance(cert.getExtension(Extension.keyUsage).getParsedValue());
    assertTrue(keyUsage.hasUsages(KeyUsage.nonRepudiation));
    assertFalse(keyUsage.hasUsages(KeyUsage.digitalSignature));
    assertNotNull(cert.getExtension(Extension.authorityKeyIdentifier));

    // Nothing from the one-signature-certificate profile
    assertNull(cert.getExtension(NO_REV_AVAIL), "noRevAvail must not be present");
    assertNull(cert.getExtension(SignedDocumentBinding.OID), "signedDocumentBinding must not be present");
    return authnContext;
  }

  /**
   * The SACI object of the example: an Identity Provider at example.com authenticated John Doe at an example assurance
   * level; the certificate subject attributes and the e-mail alt name were derived from SAML attributes.
   */
  private static SAMLAuthContext exampleSamlAuthContext() throws CertificateIssuanceException {
    return SAMLAuthContextBuilder.instance()
        .identityProvider("https://idp.example.com")
        .authenticationInstant(Date.from(AUTH_TIME))
        .authnContextClassRef("https://example.com/loa/3")
        .assertionRef("_0f3e2c6a7b1d4e4c9a2e5d1c2b3a4f60")
        .serviceID("https://sign.example.com")
        .attributeMappings(Arrays.asList(
            AttributeMappingBuilder.instance().name("urn:oid:1.2.752.29.4.13").friendlyName("personalIdentityNumber")
                .nameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
                .ref("2.5.4.5").type(AttributeMapping.Type.rdn).build(),
            AttributeMappingBuilder.instance().name("urn:oid:2.5.4.42").friendlyName("givenName")
                .nameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
                .ref("2.5.4.42").type(AttributeMapping.Type.rdn).build(),
            AttributeMappingBuilder.instance().name("urn:oid:2.5.4.4").friendlyName("sn")
                .nameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
                .ref("2.5.4.4").type(AttributeMapping.Type.rdn).build(),
            AttributeMappingBuilder.instance().name("urn:oid:2.16.840.1.113730.3.1.241").friendlyName("displayName")
                .nameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
                .ref("2.5.4.3").type(AttributeMapping.Type.rdn).build(),
            AttributeMappingBuilder.instance().name("urn:oid:0.9.2342.19200300.100.1.3").friendlyName("mail")
                .nameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
                .ref("1").type(AttributeMapping.Type.san).build()))
        .build();
  }

  /**
   * The OACI object of the example: an OpenID Provider at example.com authenticated John Doe at an example assurance
   * level; the certificate subject attributes and the e-mail alt name were derived from ID Token claims, the e-mail
   * from the UserInfo Response.
   */
  private static OIDCAuthContext exampleOidcAuthContext() throws CertificateIssuanceException {
    return OIDCAuthContextBuilder.instance()
        .iss("https://op.example.com")
        .authTime(AUTH_TIME)
        .acr("https://example.com/loa/3")
        .jti("0f3e2c6a-7b1d-4e4c-9a2e-5d1c2b3a4f60")
        .clientId("https://sign.example.com")
        .claimMappings(Arrays.asList(
            ClaimMapping.builder().type(AttributeMapping.Type.rdn).ref("2.5.4.5")
                .claim("/https:~1~1example.com~1claims~1personal_id").build(),
            ClaimMapping.builder().type(AttributeMapping.Type.rdn).ref("2.5.4.42").claim("/given_name").build(),
            ClaimMapping.builder().type(AttributeMapping.Type.rdn).ref("2.5.4.4").claim("/family_name").build(),
            ClaimMapping.builder().type(AttributeMapping.Type.rdn).ref("2.5.4.3").claim("/name").build(),
            ClaimMapping.builder().type(AttributeMapping.Type.san).ref("1").claim("/email")
                .source(ClaimMapping.Source.userinfo).build()))
        .build();
  }

  /**
   * SACI using every option of RFC 7773 Section 3 and the Sweden Connect certificate profile: attribute mappings
   * with attribute values, and Extended Authentication Information elements in the AuthContextInfo any-list.
   */
  private static SAMLAuthContext fullSamlAuthContext() throws CertificateIssuanceException {
    final Document doc = DOMUtils.createNewDocument();
    return SAMLAuthContextBuilder.instance()
        .identityProvider("https://idp.example.com")
        .authenticationInstant(Date.from(AUTH_TIME))
        .authnContextClassRef("https://example.com/loa/3")
        .assertionRef("_0f3e2c6a7b1d4e4c9a2e5d1c2b3a4f60")
        .serviceID("https://sign.example.com")
        .extensions(Arrays.asList(
            extAuthInfo(doc, TRANSACTION_ID_ATTRIBUTE, TRANSACTION_ID),
            extAuthInfo(doc, "https://example.com/attributes/sign-message-digest",
                "SHA-256;4bXBKVlJfsLBddtRcnvQnFhGvCqwNmWBPD6iOJ6oaIk=")))
        .attributeMappings(Arrays.asList(
            AttributeMappingBuilder.instance().name("urn:oid:1.2.752.29.4.13").friendlyName("personalIdentityNumber")
                .nameFormat(URI_NAME_FORMAT).ref("2.5.4.5").type(AttributeMapping.Type.rdn)
                .attributeStringValue("198001011234").build(),
            AttributeMappingBuilder.instance().name("urn:oid:2.5.4.42").friendlyName("givenName")
                .nameFormat(URI_NAME_FORMAT).ref("2.5.4.42").type(AttributeMapping.Type.rdn)
                .attributeStringValue("John").build(),
            AttributeMappingBuilder.instance().name("urn:oid:2.5.4.4").friendlyName("sn")
                .nameFormat(URI_NAME_FORMAT).ref("2.5.4.4").type(AttributeMapping.Type.rdn)
                .attributeStringValue("Doe").build(),
            AttributeMappingBuilder.instance().name("urn:oid:2.16.840.1.113730.3.1.241").friendlyName("displayName")
                .nameFormat(URI_NAME_FORMAT).ref("2.5.4.3").type(AttributeMapping.Type.rdn)
                .attributeStringValue("John Doe").build(),
            AttributeMappingBuilder.instance().name("urn:oid:0.9.2342.19200300.100.1.3").friendlyName("mail")
                .nameFormat(URI_NAME_FORMAT).ref("1").type(AttributeMapping.Type.san)
                .attributeStringValue("john.doe@example.com").build()))
        .build();
  }

  /** Creates a {@code <sacex:ExtAuthInfo Name="...">value</sacex:ExtAuthInfo>} element. */
  private static Element extAuthInfo(final Document doc, final String name, final String value) {
    final Element element = doc.createElementNS(SACEX_NS, "sacex:ExtAuthInfo");
    element.setAttribute("Name", name);
    element.setTextContent(value);
    return element;
  }

  /**
   * OACI using every member of draft-santesson-oidc-cert-auth-context, plus additional members as permitted by the
   * specification. Note that the Sweden Connect certificate profile forbids the {@code amr} member; this variant
   * shows the maximum of the specification, not a profile-conformant certificate.
   */
  private static OIDCAuthContext fullOidcAuthContext() throws CertificateIssuanceException {
    return OIDCAuthContextBuilder.instance()
        .iss("https://op.example.com")
        .authTime(AUTH_TIME)
        .acr("https://example.com/loa/3")
        .amr(Arrays.asList("sc", "pin"))
        .jti("0f3e2c6a-7b1d-4e4c-9a2e-5d1c2b3a4f60")
        .sub("a1b2c3d4e5f60718293a4b5c6d7e8f90")
        .clientId("https://sign.example.com")
        .claimMappings(Arrays.asList(
            ClaimMapping.builder().type(AttributeMapping.Type.rdn).ref("2.5.4.5")
                .claim("/https:~1~1example.com~1claims~1personal_id")
                .source(ClaimMapping.Source.id_token).build(),
            ClaimMapping.builder().type(AttributeMapping.Type.rdn).ref("2.5.4.42").claim("/given_name").build(),
            ClaimMapping.builder().type(AttributeMapping.Type.rdn).ref("2.5.4.4").claim("/family_name").build(),
            ClaimMapping.builder().type(AttributeMapping.Type.rdn).ref("2.5.4.3").claim("/name").build(),
            ClaimMapping.builder().type(AttributeMapping.Type.san).ref("1").claim("/email")
                .source(ClaimMapping.Source.userinfo).build()))
        .additionalMember("https://example.com/claims/transaction_id", TRANSACTION_ID)
        .additionalMember("https://example.com/claims/sign_message_displayed", true)
        .build();
  }

  /** John Doe, with the attributes referenced by the claim mappings. */
  private static CertNameModel<?> johnDoe() {
    return new ExplicitCertNameModel(Arrays.asList(
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.O).value("Example Org").build(),
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SERIALNUMBER).value("198001011234").build(),
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.GIVENNAME).value("John").build(),
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SURNAME).value("Doe").build(),
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value("John Doe").build()));
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
