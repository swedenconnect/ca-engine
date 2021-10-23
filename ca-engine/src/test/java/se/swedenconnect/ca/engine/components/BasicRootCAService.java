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
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.issuer.impl.AbstractCAService;
import se.swedenconnect.ca.engine.ca.issuer.impl.BasicCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuer;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;
import se.swedenconnect.ca.engine.revocation.crl.impl.DefaultCRLIssuer;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Basic Root CA service for test
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class BasicRootCAService extends AbstractCAService<DefaultCertificateModelBuilder> {

  private final File crlFile;
  @Getter private CertificateIssuer certificateIssuer;
  private CRLIssuer crlIssuer;
  private List<String> crlDistributionPoints;

  public BasicRootCAService(PrivateKey privateKey, X509CertificateHolder caCertificate, CARepository caRepository,
    File crlFile, String algorithm) throws Exception {
    super(Arrays.asList(caCertificate), caRepository);
    this.crlFile = crlFile;
    this.certificateIssuer = new BasicCertificateIssuer(
      new CertificateIssuerModel(algorithm, 10), getCaCertificate().getSubject(), privateKey);
    CRLIssuerModel crlIssuerModel = getCrlIssuerModel(getCaRepository().getCRLRevocationDataProvider(), algorithm);
    this.crlDistributionPoints = new ArrayList<>();
    if (crlIssuerModel != null) {
      this.crlIssuer = new DefaultCRLIssuer(crlIssuerModel, privateKey);
      this.crlDistributionPoints = Arrays.asList(crlIssuerModel.getDistributionPointUrl());
      publishNewCrl();
    }
  }

  private CRLIssuerModel getCrlIssuerModel(CRLRevocationDataProvider crlRevocationDataProvider, String algorithm)
    throws CertificateRevocationException {
    try {
      return new CRLIssuerModel(getCaCertificate(), algorithm,
        2, crlRevocationDataProvider, TestCAProvider.getFileUrl(crlFile));
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

  @Override public OCSPResponder getOCSPResponder() {
    return null;
  }

  @Override public X509CertificateHolder getOCSPResponderCertificate() {
    return null;
  }

  @Override protected DefaultCertificateModelBuilder getBaseCertificateModelBuilder(CertNameModel subject, PublicKey publicKey,
    X509CertificateHolder issuerCertificate, CertificateIssuerModel certificateIssuerModel) throws CertificateIssuanceException {
    DefaultCertificateModelBuilder certModelBuilder = DefaultCertificateModelBuilder.getInstance(publicKey, getCaCertificate(),
      certificateIssuerModel);
    certModelBuilder
      .subject(subject)
      .includeAki(true)
      .includeSki(true)
      .basicConstraints(new BasicConstraintsModel(true, true))
      .keyUsage(new KeyUsageModel(KeyUsage.keyCertSign + KeyUsage.cRLSign))
      .certificatePolicy(new CertificatePolicyModel(true))
      .crlDistributionPoints(crlDistributionPoints.isEmpty() ? null : crlDistributionPoints);

    return certModelBuilder;
  }

}
