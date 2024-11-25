/*
 * Copyright 2024 Agency for Digital Government (DIGG)
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
package se.swedenconnect.ca.engine.revocation.ocsp.impl;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;

import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPModel;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPStatusCheckingException;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * OCSP responder issuing responses based on data from the CA repository.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class RepositoryBasedOCSPResponder extends AbstractOCSPResponder {

  /** The repository holding information about all issued certificates */
  private final CARepository caRepository;

  /**
   * Constructor.
   *
   * @param ocspIssuerCredential the private key object used to sign OCSP responses
   * @param ocspModel OCSP responder configuration data
   * @param caRepository CA repository
   * @throws NoSuchAlgorithmException if the selected algorithm is not supported
   */
  public RepositoryBasedOCSPResponder(final PkiCredential ocspIssuerCredential, final OCSPModel ocspModel,
      final CARepository caRepository) throws NoSuchAlgorithmException {
    super(ocspIssuerCredential, ocspModel);
    this.caRepository = caRepository;
  }

  /** {@inheritDoc} */
  @Override
  protected CertificateStatus getCertStatus(final BigInteger certificateSerial) throws OCSPStatusCheckingException {

    // Get the certificate record from the CA repository
    final CertificateRecord certificateRecord = this.caRepository.getCertificate(certificateSerial);
    if (certificateRecord == null) {
      // No such certificate is known to the system. Respond with unknown status
      return new UnknownStatus();
    }
    if (certificateRecord.isRevoked()) {
      final int reason = certificateRecord.getReason() != null ? certificateRecord.getReason() : CRLReason.unspecified;
      return new RevokedStatus(certificateRecord.getRevocationTime(), reason);
    }
    return CertificateStatus.GOOD;
  }

  /** {@inheritDoc} */
  @Override
  protected void validateRequest(final TBSRequest tbsRequest) throws OCSPStatusCheckingException {
    super.validateRequest(tbsRequest);
    // Extend request validation here if necessary.
  }

}
