/*
 * Copyright 2021-2025 Sweden Connect
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

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.OperatorCreationException;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;
import se.swedenconnect.ca.engine.revocation.crl.CRLMetadata;
import se.swedenconnect.ca.engine.revocation.crl.RevokedCertificate;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Implementation of a synchronized CRL issuer.
 *
 * <p>This CRL issuer supports presence of multiple clustered deployment of CA services issuing
 * CRLs with synchronized CRL number, issue time, next update time and revocation content
 * based on synchronized metadata from the latest published CRL from any instance in the
 * cluster</p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class SynchronizedCRLIssuer extends AbstractCRLIssuer {

  /** Configuration data for this CRL issuer */
  protected final CRLIssuerModel crlIssuerModel;

  /**
   * Constructor.
   *
   * @param crlIssuerModel the CRL issuer model holding essential configuration data
   * @param crlRevocationDataProvider provider of CRL revocation data regarding the state of revoked certificates
   * @param issuerCredential the credential used to sign CRLs
   * @throws NoSuchAlgorithmException if the issuer model algorithm is not supported
   */
  public SynchronizedCRLIssuer(final CRLIssuerModel crlIssuerModel, final CRLRevocationDataProvider crlRevocationDataProvider,
    final PkiCredential issuerCredential)
    throws NoSuchAlgorithmException {
    super(issuerCredential, crlIssuerModel.getAlgorithm(), crlRevocationDataProvider);
    this.crlIssuerModel = crlIssuerModel;
  }

  /** {@inheritDoc} */
  @Override
  public X509CRLHolder issueCRL() throws CertificateRevocationException {

    log.debug("Issuing CRL");

    try {
      final X509Certificate issuerCert = CAUtils.getCert(this.crlIssuerModel.getIssuerCertificate());
      final List<RevokedCertificate> revokedCertificates = crlRevocationDataProvider.getRevokedCertificates();
      RevocationSettings revocationSettings = getCrlRevocationSettings(revokedCertificates);

      final JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(issuerCert, Date.from(revocationSettings.getIssueTime()));
      builder.addExtension(Extension.cRLNumber, false, new CRLNumber(revocationSettings.getCrlNumber()));
      builder.addExtension(Extension.authorityKeyIdentifier, false, this.getAki());
      builder.addExtension(Extension.issuingDistributionPoint, true, new IssuingDistributionPoint(
          new DistributionPointName(
              new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier,
                  this.crlIssuerModel.getDistributionPointUrl()))),
          this.crlIssuerModel.isOnlyEECerts(),
          this.crlIssuerModel.isOnlyCACerts(),
          this.crlIssuerModel.getOnlySomeReasons(),
          this.crlIssuerModel.isIndirectCrl(), false));

      // set issuing data and next update
      builder.setNextUpdate(Date.from(revocationSettings.getNextUpdateTime()));

      for (final RevokedCertificate revokedCertificate : revokedCertificates) {
        builder.addCRLEntry(
            revokedCertificate.getCertificateSerialNumber(),
            revokedCertificate.getRevocationTime(),
            revokedCertificate.getReason());
      }
      return builder.build(this.getContentSigner());
    }
    catch (IOException | CertificateException ex) {
      log.error("Failed to issue CRL", ex);
      throw new CertificateRevocationException("Failed to issue CRL", ex);
    }
    catch (final OperatorCreationException ex) {
      log.error("Failed to create CRL content signer", ex);
      throw new CertificateRevocationException("Failed to create CRL content signer", ex);
    }
  }

  /**
   * The strategy implemented here is that a CRL using existing CRL number and issue time will be chosen unless
   * there is a condition for force update, upon which a new CRL with new CRL number and issue time will be created.
   *
   * <p>
   *   The force update conditions are:*
   * </p>
   * <ul>
   *   <li>The number of revoked certificates from last CRL differs from current CA repository count</li>
   *   <li>The current CRL has expired</li>
   *   <li>The maxDurationBeforeCRLUpgrade is not null and this duration has passed since current CRL was created</li>
   * </ul>
   *
   * @param revokedCertificates the currently revoked certificates registered in the CA repository
   * @return The settings for the CRL to be created.
   */
  protected RevocationSettings getCrlRevocationSettings(List<RevokedCertificate> revokedCertificates) {

    log.debug("Determining if CRL will be issued as new CRL with new CRL number, or as a clone of current"
      + "CRL metadata");

    CRLMetadata CRLMetadata = crlRevocationDataProvider.getCurrentCRLMetadata();
    if (CRLMetadata == null) {
      log.debug("No CRL metadata is available. Issuing new CRL");
      return getNewCRLSettings();
    }
    // Is current CRL expired
    Instant now = Instant.now();
    if (now.isAfter(CRLMetadata.getNextUpdate())){
      log.debug("Current CRL has expired. Issue new CRL");
      return getNewCRLSettings();
    }
    // Is max duration set and expired
    if (crlIssuerModel.getMaxDurationBeforeCRLUpgrade() != null) {
      // Max age is the time after actual issue time. As such it is adjusted against the pre-issue time set by the CRL issuer model
      Instant maxAge = Instant.ofEpochMilli(
        CRLMetadata.getIssueTime().toEpochMilli()
          - crlIssuerModel.getStartOffset().toMillis()
          + crlIssuerModel.getMaxDurationBeforeCRLUpgrade().toMillis());
      if (now.isAfter(maxAge)){
        log.debug("Current CRL metadata is older than max age {}. Issue new CRL", maxAge);
        return getNewCRLSettings();
      }
    }
    // Has number of revoked certificates changed?
    if (CRLMetadata.getRevokedCertCount() != revokedCertificates.size()) {
      log.debug("Number of revoked certificates has changed. Issue new CRL");
      return getNewCRLSettings();
    }

    log.debug("Current CRL metadata is current and valid. Issue clone CRL based on CRL metadata");
    // No force update conditions. Re-use current CRL settings
    return RevocationSettings.builder()
      .issueTime(CRLMetadata.getIssueTime())
      .nextUpdateTime(CRLMetadata.getNextUpdate())
      .crlNumber(CRLMetadata.getCrlNumber())
      .build();

  }

  private RevocationSettings getNewCRLSettings() {
    return RevocationSettings.builder()
      .issueTime(CertificateIssuer.getOffsetTime(this.crlIssuerModel.getStartOffset()).toInstant())
      .nextUpdateTime(CertificateIssuer.getOffsetTime(this.crlIssuerModel.getExpiryOffset()).toInstant())
      .crlNumber(crlRevocationDataProvider.getNextCrlNumber())
      .build();
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  static class RevocationSettings {
    /** The issue time for the CRL to create */
    Instant issueTime;
    /** Next update time for the CRL to create */
    Instant nextUpdateTime;
    /** The CRL number for the CRL to create */
    BigInteger crlNumber;
  }

}
