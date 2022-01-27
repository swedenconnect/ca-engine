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

package se.swedenconnect.ca.engine.components;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.issuer.impl.SelfIssuedCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.ExtendedKeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.SelfIssuedCertificateModelBuilder;
import se.swedenconnect.ca.engine.data.TestCa;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPModel;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.ca.engine.revocation.ocsp.impl.RepositoryBasedOCSPResponder;

import java.io.File;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;

/**
 * This class when instantiated creates 2 CA services and related revocation services for CRL adn OCSP revocation checking.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class TestCAProvider {

  public static final String FILE_URL_PREFIX = "http://file.example.com/";

  private final File dataDir;
  @Getter private BasicRootCAService rootCA;
  @Getter private BasicIssuerCAService ca;
  @Getter public final TestCa caConfig;

  public TestCAProvider(TestCa caConfig) {
    this.dataDir = new File(System.getProperty("user.dir"), "target/test/ca-repo");
    this.caConfig = caConfig;
    try {
      setupCAs();
    }
    catch (Exception e) {
      e.printStackTrace();
    }
  }

  private void setupCAs() throws Exception {
    log.info("Setting up test CA {}", caConfig.getId());
    rootCA = createRootCA();
    ca = createIssuerCA();
    addOCSPResponder();
  }

  private BasicIssuerCAService createIssuerCA() throws Exception {
    log.info("Generating ca key for {}", caConfig.getId());
    KeyPair kp = caConfig.getCaKeyPair();
    CertNameModel name = getCAName(caConfig.getCaName());
    DefaultCertificateModelBuilder builder = rootCA.getCertificateModelBuilder(name, kp.getPublic());

    // Add OCSP capability if there is not OSCP key
    // This is removed since the OCSP signing key should not require
/*
    if (caConfig.getOcspKeyPair() == null) {
      builder
        .keyUsage(new KeyUsageModel(KeyUsage.keyCertSign + KeyUsage.cRLSign + KeyUsage.digitalSignature, true))
        .extendedKeyUsage(new ExtendedKeyUsageModel(false, KeyPurposeId.id_kp_OCSPSigning));
    }
*/

    X509CertificateHolder caCert = rootCA.issueCertificate(builder.build());
    List<X509CertificateHolder> caCertChain = Arrays.asList(caCert, rootCA.getCaCertificate());
    File crlFile = new File(dataDir, caConfig.getId() + "/ca.crl");
    return new BasicIssuerCAService(kp.getPrivate(), caCertChain, new TestCARepository(crlFile), crlFile, caConfig.getCaAlgo());
  }

  private BasicRootCAService createRootCA() throws Exception {
    // generate key and root CA cert
    CertificateIssuer certificateIssuer = new SelfIssuedCertificateIssuer(new CertificateIssuerModel(
      caConfig.getRootAlgo(),
      20
    ));

    log.info("Generating root ca key for {}", caConfig.getId());
    KeyPair kp = caConfig.getRootKeyPair();
    CertNameModel name = getCAName(caConfig.getRootName());

    CertificateModelBuilder builder = SelfIssuedCertificateModelBuilder.getInstance(kp, certificateIssuer.getCertificateIssuerModel())
      .subject(name)
      .basicConstraints(new BasicConstraintsModel(true, true))
      .includeSki(true)
      .keyUsage(new KeyUsageModel(KeyUsage.keyCertSign + KeyUsage.cRLSign, true))
      .certificatePolicy(new CertificatePolicyModel(true));
    X509CertificateHolder rootCA01Cert = certificateIssuer.issueCertificate(builder.build());
    File crlFile = new File(dataDir, caConfig.getId() + "/root-ca.crl");

    return new BasicRootCAService(kp.getPrivate(), rootCA01Cert, new TestCARepository(crlFile), crlFile, caConfig.getRootAlgo());
  }

  private CertNameModel getCAName(String commonName) {
    return new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.C)
        .value("SE").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.O)
        .value("Test Org").build(),
      AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.CN)
        .value(commonName).build()
    ));
  }

  private void addOCSPResponder() {
    try {
      log.info("Generating ocsp responder key for {}", caConfig.getId());

      KeyPair kp;
      String algorithm;
      List<X509CertificateHolder> ocspServiceChain;
      if (caConfig.getOcspKeyPair() != null) {
        // There is a dedicated key for OCSP responses. Setup an authorized responder
        kp = caConfig.getOcspKeyPair();
        algorithm = caConfig.getOcspAlgo();
        DefaultCertificateModelBuilder certModelBuilder = ca.getCertificateModelBuilder(
          CertRequestData.getTypicalServiceName(caConfig.getOcspName()), kp.getPublic());

        certModelBuilder
          .qcStatements(null)
          .keyUsage(new KeyUsageModel(KeyUsage.digitalSignature))
          .crlDistributionPoints(null)
          .ocspServiceUrl(null)
          .ocspNocheck(true)
          .extendedKeyUsage(new ExtendedKeyUsageModel(true, KeyPurposeId.id_kp_OCSPSigning));

        X509CertificateHolder ocspIssuerCert = ca.issueCertificate(certModelBuilder.build());
        ocspServiceChain = Arrays.asList(
          ocspIssuerCert,
          ca.getCaCertificate(),
          rootCA.getCaCertificate()
        );

      }
      else {
        // We are issuing OCSP response directly from CA
        kp = caConfig.getCaKeyPair();
        algorithm = caConfig.getCaAlgo();
        ocspServiceChain = Arrays.asList(
          ca.getCaCertificate(),
          rootCA.getCaCertificate());
      }

      OCSPModel ocspModel = new OCSPModel(ocspServiceChain, ca.getCaCertificate(), algorithm);
      OCSPResponder ocspResponder = new RepositoryBasedOCSPResponder(kp.getPrivate(), ocspModel, ca.getCaRepository());
      ca.setOcspResponder(ocspResponder, "https://example.com/" + caConfig.getId() + "/ocsp", ocspServiceChain.get(0));
    }
    catch (Exception ex) {
      log.error("Error creating OCSP responder", ex);
    }
  }

  public static String getFileUrl(File file) {
    return getFileUrl(file.getAbsolutePath());
  }

  public static String getFileUrl(String path) {
    String urlEncodedPath = URLEncoder.encode(path, StandardCharsets.UTF_8);
    return FILE_URL_PREFIX + urlEncodedPath;
  }

}
