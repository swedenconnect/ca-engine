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

package se.swedenconnect.ca.engine.revocation.ocsp.impl;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPModel;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPStatusCheckingException;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

/**
 * OCSP responder issuing responses based on data from the CA repository
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class RepositoryBasedOCSPResponder extends AbstractOCSPResponder {

  /** The repository holding information about all issued certificates */
  private final CARepository caRepository;

  /**
   * @param privateKey   the private key object used to sign OCSP responses
   * @param ocspModel    OCSP responder configuration data
   * @param caRepository CA repository
   * @throws NoSuchAlgorithmException if the selected algorithm is not supported
   */
  public RepositoryBasedOCSPResponder(PrivateKey privateKey, OCSPModel ocspModel,
    CARepository caRepository) throws NoSuchAlgorithmException {
    super(privateKey, ocspModel);
    this.caRepository = caRepository;
  }

  /** {@inheritDoc} */
  @Override protected CertificateStatus getCertStatus(BigInteger certificateSerial) throws OCSPStatusCheckingException {

    // Get the certificate record from the CA repository
    CertificateRecord certificateRecord = caRepository.getCertificate(certificateSerial);
    if (certificateRecord == null) {
      // No such certificate is known to the system. Respond with unknown status
      return new UnknownStatus();
    }
    if (certificateRecord.isRevoked()) {
      int reason = certificateRecord.getReason() != null ? certificateRecord.getReason() : CRLReason.unspecified;
      return new RevokedStatus(certificateRecord.getRevocationTime(), reason);
    }
    return CertificateStatus.GOOD;
  }

  /** {@inheritDoc} */
  @Override protected void validateRequest(TBSRequest tbsRequest) throws OCSPStatusCheckingException {
    super.validateRequest(tbsRequest);
    // Extend request validation here if necessary.
  }

}
