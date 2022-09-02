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

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

import lombok.Getter;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuer;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * This class provides an abstract skeleton for a typical CA service by combining the functions of a CertificateIssuer,
 * a CRLIssuer and a CARepository.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractCAService<T extends CertificateModelBuilder> implements CAService {

  private final List<X509CertificateHolder> caCertificateChain;

  @Getter
  private final CARepository caRepository;

  /**
   * Constructor for the CA service
   *
   * @param issuerCredential ths issuing credentials of this CA service with the CA certificate first
   *          and the trust anchor la
   * @param caRepository repository for certificate and revocation data
   */
  public AbstractCAService(PkiCredential issuerCredential, final CARepository caRepository)
    throws CertificateEncodingException {
    this.caCertificateChain = CAUtils.getCertificateHolderList(issuerCredential.getCertificateChain());
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
  @Override
  public abstract OCSPResponder getOCSPResponder();

  /**
   * Implementations of this method provide a base certificate model containing all information that is common for all
   * issued certificates as well as all information that can be derived from the subject name, the public key and the
   * issuer certificate.
   *
   * @param subject subject name
   * @param publicKey public key
   * @param issuerCertificate issuer certificate
   * @param certificateIssuerModel the certificate issuing model
   * @return base certificate model for issuing a certificate
   * @throws CertificateIssuanceException on errors creating the certificate model
   */
  protected abstract T getBaseCertificateModelBuilder(CertNameModel<?> subject, PublicKey publicKey,
      X509CertificateHolder issuerCertificate, CertificateIssuerModel certificateIssuerModel)
      throws CertificateIssuanceException;

  /** {@inheritDoc} */
  @Override
  public T getCertificateModelBuilder(final CertNameModel<?> subject, final PublicKey publicKey)
      throws CertificateIssuanceException {
    return this.getBaseCertificateModelBuilder(subject, publicKey, this.getCaCertificate(),
        this.getCertificateIssuer().getCertificateIssuerModel());
  }

  /** {@inheritDoc} */
  @Override
  public X509CertificateHolder issueCertificate(final CertificateModel certificateModel)
      throws CertificateIssuanceException {
    final X509CertificateHolder certificate = this.getCertificateIssuer().issueCertificate(certificateModel);
    try {
      this.caRepository.addCertificate(certificate);
    }
    catch (final IOException e) {
      throw new CertificateIssuanceException(e);
    }
    return certificate;
  }

  /** {@inheritDoc} */
  @Override
  public void revokeCertificate(final BigInteger serialNumber, final Date revocationDate)
      throws CertificateRevocationException {
    this.revokeCertificate(serialNumber, CRLReason.unspecified, revocationDate);
  }

  /** {@inheritDoc} */
  @Override
  public void revokeCertificate(final BigInteger serialNumber, final int reason, Date revocationDate)
      throws CertificateRevocationException {
    // Check that date is set and not a future date
    if (revocationDate == null || revocationDate.after(new Date())) {
      revocationDate = new Date();
    }

    // Check for existence and previous revocation
    final CertificateRecord certificateRecord = this.caRepository.getCertificate(serialNumber);
    if (certificateRecord == null) {
      throw new CertificateRevocationException("Certificate serial number for revocation does not exist");
    }
    if (certificateRecord.isRevoked()) {
      // Check is status is special status on-hold
      if (certificateRecord.getReason() != CRLReason.certificateHold) {
        throw new CertificateRevocationException(
            "Certificate serial number for revocation has already been permanently revoked");
      }
      else {
        // This certificate was previously revoked with reason "on hold". Use original revocation time.
        revocationDate = certificateRecord.getRevocationTime();
      }
    }
    this.caRepository.revokeCertificate(serialNumber, reason, revocationDate);
  }

  /** {@inheritDoc} */
  @Override
  public X509CRLHolder publishNewCrl() throws IOException {
    final CRLIssuer crlIssuer = this.getCrlIssuer();
    if (crlIssuer != null) {
      final X509CRLHolder newCrl = crlIssuer.issueCRL();
      this.caRepository.getCRLRevocationDataProvider().publishNewCrl(newCrl);
      return newCrl;
    }
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public X509CRLHolder getCurrentCrl() {
    return this.caRepository.getCRLRevocationDataProvider().getCurrentCrl();
  }

  @Override
  public X509CertificateHolder getCaCertificate() {
    return this.caCertificateChain.get(0);
  }

  @Override
  public List<X509CertificateHolder> getCACertificateChain() {
    return this.caCertificateChain;
  }

}
