/*
 * Copyright 2021-2023 Agency for Digital Government (DIGG)
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

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.issuer.impl.AbstractCAService;
import se.swedenconnect.ca.engine.ca.issuer.impl.BasicCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.data.QcStatementsBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuer;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.engine.revocation.crl.impl.SynchronizedCRLIssuer;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Basic CA service implementation for test
 *
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class BasicIssuerCAService extends AbstractCAService<DefaultCertificateModelBuilder> {

  private final File crlFile;
  private CertificateIssuer certificateIssuer;
  private CRLIssuer crlIssuer;
  private List<String> crlDistributionPoints;
  private OCSPResponder ocspResponder;
  private X509CertificateHolder ocspResponderCertificate;
  private String ocspResponderUrl;

  public BasicIssuerCAService(PkiCredential issuerCredential,
    CARepository caRepository, File crlFile, String algorithm)
    throws CertificateEncodingException, NoSuchAlgorithmException, IOException {
    super(issuerCredential, caRepository);
    this.crlFile = crlFile;
    this.certificateIssuer = new BasicCertificateIssuer(
      new CertificateIssuerModel(algorithm, Duration.ofDays(365)), issuerCredential);
    CRLIssuerModel crlIssuerModel = getCrlIssuerModel(algorithm);
    this.crlDistributionPoints = new ArrayList<>();
    if (crlIssuerModel != null) {
      this.crlIssuer = new SynchronizedCRLIssuer(crlIssuerModel, caRepository.getCRLRevocationDataProvider(),
        issuerCredential);
      this.crlDistributionPoints = Arrays.asList(crlIssuerModel.getDistributionPointUrl());
      publishNewCrl();
    }
  }

  private CRLIssuerModel getCrlIssuerModel(String algorithm)
    throws CertificateRevocationException {
    try {
      return new CRLIssuerModel(getCaCertificate(), algorithm,
        Duration.ofHours(2), TestCAProvider.getFileUrl(crlFile));
    }
    catch (Exception e) {
      throw new CertificateRevocationException(e);
    }
  }

  @Override public CertificateIssuer getCertificateIssuer() {
    return certificateIssuer;
  }

  @Override protected CRLIssuer getCrlIssuer() {
    return crlIssuer;
  }

  @Override
  public X509CertificateHolder getOCSPResponderCertificate() {
    return ocspResponderCertificate;
  }

  @Override public String getCaAlgorithm() {
    return certificateIssuer.getCertificateIssuerModel().getAlgorithm();
  }

  @Override public List<String> getCrlDpURLs() {
    return crlDistributionPoints;
  }

  @Override public String getOCSPResponderURL() {
    return ocspResponderUrl;
  }

  public void setOcspResponder(OCSPResponder ocspResponder, String ocspResponderUrl,
    X509CertificateHolder ocspResponderCertificate) {
    this.ocspResponder = ocspResponder;
    this.ocspResponderUrl = ocspResponderUrl;
    this.ocspResponderCertificate = ocspResponderCertificate;
  }

  @Override public OCSPResponder getOCSPResponder() {
    return ocspResponder;
  }

  @Override protected DefaultCertificateModelBuilder getBaseCertificateModelBuilder(CertNameModel<?> subject,
    PublicKey publicKey,
    X509CertificateHolder issuerCertificate, CertificateIssuerModel certificateIssuerModel)
    throws CertificateIssuanceException {
    DefaultCertificateModelBuilder certModelBuilder = DefaultCertificateModelBuilder.getInstance(publicKey,
      getCaCertificate(),
      certificateIssuerModel);
    certModelBuilder
      .subject(subject)
      .includeAki(true)
      .includeSki(true)
      .basicConstraints(new BasicConstraintsModel(false, true))
      .keyUsage(new KeyUsageModel(KeyUsage.digitalSignature + KeyUsage.nonRepudiation + KeyUsage.keyEncipherment))
      .certificatePolicy(new CertificatePolicyModel(false, new ASN1ObjectIdentifier("2.3.4.5.6")))
      .qcStatements(QcStatementsBuilder.instance()
        .qualifiedCertificate(true)
        .qscd(true)
        .build())
      .crlDistributionPoints(crlDistributionPoints.isEmpty() ? null : crlDistributionPoints)
      .ocspServiceUrl(ocspResponder != null ? ocspResponderUrl : null);

    return certModelBuilder;
  }

}
