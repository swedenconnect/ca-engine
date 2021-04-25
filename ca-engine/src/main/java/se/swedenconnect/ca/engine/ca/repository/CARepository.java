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

package se.swedenconnect.ca.engine.ca.repository;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;

/**
 * Interface for implementing a CA repository
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CARepository {

  /**
   * Gets a list of all current certificate serial numbers of certificates in the repository
   *
   * @return List of certificate serial numbers
   */
  List<BigInteger> getAllCertificates();

  /**
   * Gets the certificate data associated with a certificate serial number
   *
   * @param serialNumber certificate serial number
   * @return certificate record or null if there is not record available for this certificate
   */
  CertificateRecord getCertificate(BigInteger serialNumber);

  /**
   * Add a certificate to the certificate repository
   *
   * @param certificate certificate to add to the repository
   * @throws IOException on failure to add the certificate
   */
  void addCertificate(X509CertificateHolder certificate) throws IOException;

  /**
   * Revoke a certificate at a particular date at a particular time
   *
   * @param serialNumber   certificate serial number
   * @param reason         revocation reason
   * @param revocationTime revocation time
   * @throws CertificateRevocationException error revoking the certificate with the specified serial number
   */
  void revokeCertificate(BigInteger serialNumber, int reason, Date revocationTime) throws CertificateRevocationException;

  /**
   * Get CRL revocation data provider. This is only present if the CA supports CRL publishing.
   *
   * @return {@link CRLRevocationDataProvider} if present or else null
   */
  CRLRevocationDataProvider getCRLRevocationDataProvider();

}