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

package se.swedenconnect.ca.engine.ca.issuer.impl;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuer;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Date;
import java.util.List;

/**
 * This class provides an abstract skeleton for a typical CA service by combining the functions of a CertificateIssuer, a CRLIssuer
 * and a CARepository.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractCAService<T extends CertificateModelBuilder> implements CAService {

  @Getter private final List<X509CertificateHolder> caCertificateChain;
  @Getter private final CARepository caRepository;

  /**
   * Constructor for the CA service
   *
   * @param caCertificateChain the certificate chain for the public key of this CA service with the CA certificate first and the trust anchor la
   * @param caRepository  repository for certificate and revocation data
   */
  public AbstractCAService(List<X509CertificateHolder> caCertificateChain, CARepository caRepository) {
    this.caCertificateChain = caCertificateChain;
    this.caRepository = caRepository;
  }

  /**
   * Get the Certificate issuer instance for this CA service
   *
   * @return {@link CertificateIssuer}
   */
  protected abstract CertificateIssuer getCertificateIssuer();

  /**
   * Get the CRL issuer instance for this CA service
   *
   * @return {@link CRLIssuer}
   */
  protected abstract CRLIssuer getCrlIssuer();

  /** {@inheritDoc} */
  public abstract OCSPResponder getOCSPResponder();

  /**
   * Implementations of this method provide a base certificate model containing all information that is common for
   * all issued certificates as well as all information that can be derived from the subject name, the public key and
   * the issuer certificate.
   *
   * @param subject                subject name
   * @param publicKey              public key
   * @param issuerCertificate      issuer certificate
   * @param certificateIssuerModel the certificate issuing model
   * @return base certificate model for issuing a certificate
   * @throws CertificateIssuanceException on errors creating the certificate model
   */
  protected abstract T getBaseCertificateModelBuilder(CertNameModel subject, PublicKey publicKey, X509CertificateHolder issuerCertificate,
    CertificateIssuerModel certificateIssuerModel) throws CertificateIssuanceException;

  /** {@inheritDoc} */
  @Override public T getCertificateModelBuilder(CertNameModel subject, PublicKey publicKey) throws CertificateIssuanceException {
    return getBaseCertificateModelBuilder(subject, publicKey, getCaCertificate(), getCertificateIssuer().getCertificateIssuerModel());
  }

  /** {@inheritDoc} */
  @Override public X509CertificateHolder issueCertificate(CertificateModel certificateModel) throws CertificateIssuanceException {
    X509CertificateHolder certificate = getCertificateIssuer().issueCertificate(certificateModel);
    try {
      caRepository.addCertificate(certificate);
    }
    catch (IOException e) {
      throw new CertificateIssuanceException(e);
    }
    return certificate;
  }

  /** {@inheritDoc} */
  @Override public void revokeCertificate(BigInteger serialNumber, Date revocationDate) throws CertificateRevocationException {
    revokeCertificate(serialNumber, CRLReason.unspecified, revocationDate);
  }

  /** {@inheritDoc} */
  @Override public void revokeCertificate(BigInteger serialNumber, int reason, Date revocationDate) throws CertificateRevocationException {
    caRepository.revokeCertificate(serialNumber, reason, revocationDate);
  }

  /** {@inheritDoc} */
  @Override public X509CRLHolder publishNewCrl() throws CertificateRevocationException {
    CRLIssuer crlIssuer = getCrlIssuer();
    if (crlIssuer != null) {
      X509CRLHolder newCrl = crlIssuer.issueCRL();
      caRepository.getCRLRevocationDataProvider().publishNewCrl(newCrl);
      return newCrl;
    }
    return null;
  }

  /** {@inheritDoc} */
  @Override public X509CRLHolder getCurrentCrl() {
    return caRepository.getCRLRevocationDataProvider().getCurrentCrl();
  }

  @Override public X509CertificateHolder getCaCertificate() {
    return caCertificateChain.get(0);
  }

  @Override public List<X509CertificateHolder> getCACertificateChain() {
    return caCertificateChain;
  }


}
