/*
 * Copyright (c) 2021-2022. Agency for Digital Government (DIGG)
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
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;
import se.swedenconnect.ca.engine.revocation.crl.RevokedCertificate;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Default implementation of a CRL issuer.
 *
 * <p>This is deprecated. Use the Synchronized CRLIssuer instead.</p>
 */
@Slf4j
@Deprecated (forRemoval = true)
public class DefaultCRLIssuer extends AbstractCRLIssuer {

  /** Configuration data for this CRL issuer */
  protected final CRLIssuerModel crlIssuerModel;

  /**
   * Constructor.
   *
   * @param crlIssuerModel the CRL issuer model
   * @param issuerCredential the credential used to sign CRLs
   * @throws NoSuchAlgorithmException if the issuer model algorithm is not supported
   */
  public DefaultCRLIssuer(final CRLIssuerModel crlIssuerModel, CRLRevocationDataProvider crlRevocationDataProvider,
    final PkiCredential issuerCredential)
      throws NoSuchAlgorithmException {
    super(issuerCredential, crlIssuerModel.getAlgorithm(), crlRevocationDataProvider);
    this.crlIssuerModel = crlIssuerModel;
  }

  /** {@inheritDoc} */
  @Override
  public X509CRLHolder issueCRL() throws CertificateRevocationException {

    try {
      final X509Certificate issuerCert = CAUtils.getCert(this.crlIssuerModel.getIssuerCertificate());
      final Date issuedAt = CertificateIssuer.getOffsetTime(this.crlIssuerModel.getStartOffset());
      final Date nextUpdate = CertificateIssuer.getOffsetTime(this.crlIssuerModel.getExpiryOffset());

      final JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(issuerCert, issuedAt);
      final List<RevokedCertificate> revokedCertificates = crlRevocationDataProvider.getRevokedCertificates();
      builder.addExtension(Extension.cRLNumber, false, new CRLNumber(crlRevocationDataProvider.getNextCrlNumber()));
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
      builder.setNextUpdate(nextUpdate);

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

}
