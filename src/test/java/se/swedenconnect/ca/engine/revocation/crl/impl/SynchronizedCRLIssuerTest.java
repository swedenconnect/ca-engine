/*
 * Copyright 2023 Agency for Digital Government (DIGG)
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

package se.swedenconnect.ca.engine.revocation.crl.impl;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.issuer.impl.SelfIssuedCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.SelfIssuedCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.components.TestCARepository;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;
import se.swedenconnect.ca.engine.data.TestData;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuer;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.ca.engine.utils.TestUtils;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Test for the synchronized CRL Issuer
 */
@Slf4j
class SynchronizedCRLIssuerTest {

  private static PkiCredential issuerCredential;
  private static File crlFile;
  List<X509CRLHolder> crlList;
  List<String> crlB64List;
  List<CRLData> crlDataList;

  @BeforeAll
  static void init() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    CertificateIssuer certificateIssuer = new SelfIssuedCertificateIssuer(new CertificateIssuerModel(
      CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA256,
      Duration.ofDays(2 * 3650 + 5)));

    KeyPair kp = TestData.rsa2048kp02;
    CertNameModel<?> name = new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.C)
        .value("SE").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.O)
        .value("Test Org").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.CN)
        .value("SyncCRLIssuer").build()));
    ;

    File dataDir = new File(System.getProperty("user.dir"), "target/test/ca-repo");

    CertificateModelBuilder builder =
      SelfIssuedCertificateModelBuilder.getInstance(kp, certificateIssuer.getCertificateIssuerModel())
        .subject(name)
        .basicConstraints(new BasicConstraintsModel(true, true))
        .includeSki(true)
        .keyUsage(new KeyUsageModel(KeyUsage.keyCertSign + KeyUsage.cRLSign, true))
        .certificatePolicy(new CertificatePolicyModel(true));
    X509CertificateHolder rootCA01Cert = certificateIssuer.issueCertificate(builder.build());
    crlFile = new File(dataDir, "sync-crl/synced.crl");
    crlFile.getParentFile().mkdirs();
    if (crlFile.exists()) {
      crlFile.delete();
    }

    issuerCredential = new BasicCredential(List.of(CAUtils.getCert(rootCA01Cert)), kp.getPrivate());

  }

  @Test
  void issueCRL() throws Exception {

    CARepository caRepository = new TestCARepository(crlFile);
    CRLIssuerModel crlIssuerModel = new CRLIssuerModel(new JcaX509CertificateHolder(issuerCredential.getCertificate()),
      CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA256, Duration.ofHours(1), "", Duration.ofSeconds(1));

    CRLIssuer crlIssuer = new SynchronizedCRLIssuer(crlIssuerModel,
      caRepository.getCRLRevocationDataProvider(), issuerCredential);

    crlList = new ArrayList<>();
    crlB64List = new ArrayList<>();
    crlDataList = new ArrayList<>();

    addCRLData(crlIssuer, caRepository);
    logProgress(0, "Issuing first CRL");
    addCRLData(crlIssuer, caRepository);
    logProgress(1, "Issuing second CRL identical to first CRL");
    caRepository.addCertificate(new JcaX509CertificateHolder(issuerCredential.getCertificate()));
    caRepository.revokeCertificate(issuerCredential.getCertificate().getSerialNumber(), 0, new Date());
    addCRLData(crlIssuer, caRepository);
    logProgress(2, "Revoking first certificate");
    assertEquals(crlDataList.get(0).getCrlNumber(), crlDataList.get(1).getCrlNumber());
    assertEquals(crlDataList.get(0).getIssueTime(), crlDataList.get(1).getIssueTime());
    assertNotEquals(crlDataList.get(1).getCrlNumber(), crlDataList.get(2).getCrlNumber());
    assertEquals("1", crlDataList.get(0).getCrlNumber().toString());
    assertEquals("1", crlDataList.get(1).getCrlNumber().toString());
    assertEquals("2", crlDataList.get(2).getCrlNumber().toString());
    assertEquals(0, crlDataList.get(0).getRevCount());
    assertEquals(0, crlDataList.get(1).getRevCount());
    assertEquals(1, crlDataList.get(2).getRevCount());

    Thread.sleep(1000);
    addCRLData(crlIssuer, caRepository);
    logProgress(3, "Waiting for max age (1s) to pass");
    assertNotEquals(crlDataList.get(2).getCrlNumber(), crlDataList.get(3).getCrlNumber());
    assertNotEquals(crlDataList.get(2).getIssueTime(), crlDataList.get(3).getIssueTime());
    assertEquals("3", crlDataList.get(3).getCrlNumber().toString());
    assertEquals(1, crlDataList.get(3).getRevCount());
  }

  private void logProgress(int idx, String message) {

    CRLData crlData = crlDataList.get(idx);
    String crlString = crlB64List.get(idx);

    log.info("Synchronized CRL test: " + message);
    log.info("CRL number: " +  crlData.getCrlNumber());
    log.info("Revoked count: " +  crlData.getRevCount());
    log.info("Issue Time: " + timeString(crlData.getIssueTime()));
    log.info("NextUpdate: " + timeString(crlData.getNextUpdate()));
    log.info("CRL: \n" + TestUtils.base64Print(crlString));
  }

  private String timeString(Instant instant) {
    return LocalDateTime.ofInstant(instant, ZoneId.systemDefault())
      .format( DateTimeFormatter.ofLocalizedTime(FormatStyle.MEDIUM));
  }

  private void addCRLData(CRLIssuer crlIssuer, CARepository caRepository) throws Exception {
    X509CRLHolder crl = crlIssuer.issueCRL();
    caRepository.getCRLRevocationDataProvider().publishNewCrl(crl);
    crlList.add(crl);
    CRLNumber crlNumber = CRLNumber.getInstance(crl.getExtension(Extension.cRLNumber).getParsedValue());
    crlDataList.add(CRLData.builder()
      .issueTime(crl.getThisUpdate().toInstant())
      .nextUpdate(crl.getNextUpdate().toInstant())
      .crlNumber(crlNumber.getCRLNumber())
      .revCount(crl.getRevokedCertificates().size())
      .build());
    crlB64List.add(Base64.toBase64String(crl.getEncoded()));
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  @Builder
  static class CRLData {
    Instant issueTime;
    Instant nextUpdate;
    BigInteger crlNumber;
    int revCount;
  }

}