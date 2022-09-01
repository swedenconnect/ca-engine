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

package se.swedenconnect.ca.engine.revocation.crl.impl;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;
import se.swedenconnect.ca.engine.revocation.crl.RevokedCertificate;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.security.credential.PkiCredential;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * Default implementation of a CRL issuer
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultCRLIssuer extends AbstractCRLIssuer {

  /** Configuration data for this CRL issuer */
  protected final CRLIssuerModel crlIssuerModel;

  /** {@inheritDoc} */
  public DefaultCRLIssuer(CRLIssuerModel crlIssuerModel, PkiCredential issuerCredential) throws NoSuchAlgorithmException {
    super(issuerCredential, crlIssuerModel.getAlgorithm());
    this.crlIssuerModel = crlIssuerModel;
  }

  /** {@inheritDoc} */
  @Override public X509CRLHolder issueCRL() throws CertificateRevocationException {

    try {
      X509Certificate issuerCert = CAUtils.getCert(crlIssuerModel.getIssuerCertificate());
      Date issuedAt = CertificateIssuer.getOffsetTime(crlIssuerModel.getStartOffset());
      Date nextUpdate = CertificateIssuer.getOffsetTime(crlIssuerModel.getExpiryOffset());

      JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(issuerCert, issuedAt);
      CRLRevocationDataProvider CRLRevocationDataProvider = crlIssuerModel.getCRLRevocationDataProvider();
      List<RevokedCertificate> revokedCertificates = CRLRevocationDataProvider.getRevokedCertificates();
      builder.addExtension(Extension.cRLNumber, false, new CRLNumber(CRLRevocationDataProvider.getNextCrlNumber()));
      builder.addExtension(Extension.authorityKeyIdentifier, false, getAki());
      builder.addExtension(Extension.issuingDistributionPoint, true, new IssuingDistributionPoint(
        new DistributionPointName(
          new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlIssuerModel.getDistributionPointUrl()))),
        crlIssuerModel.isOnlyEECerts(),
        crlIssuerModel.isOnlyCACerts(),
        crlIssuerModel.getOnlySomeReasons(),
        crlIssuerModel.isIndirectCrl(), false
      ));

      // set issuing data and next update
      builder.setNextUpdate(nextUpdate);

      for (RevokedCertificate revokedCertificate : revokedCertificates) {
        builder.addCRLEntry(
          revokedCertificate.getCertificateSerialNumber(),
          revokedCertificate.getRevocationTime(),
          revokedCertificate.getReason());
      }

      return builder.build(getContentSigner());
    }
    catch (IOException | CertificateException ex) {
      log.error("Failed to issue CRL", ex);
      throw new CertificateRevocationException("Failed to issue CRL", ex);
    }
    catch (OperatorCreationException ex) {
      log.error("Failed to create CRL content signer", ex);
      throw new CertificateRevocationException("Failed to create CRL content signer", ex);
    }
  }

}
