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

package se.swedenconnect.ca.engine.ca.issuer;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Date;

/**
 * Interface for a CA service
 * <p>
 * The CA service provides the collective core services of a CA including certificate issuance and revocation.
 * <p>
 * This interface is not necessary to provide a CA service, but it can be a convenient collection point that consolidates
 * all the parts of the CA service and its core functions.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CAService {

  /**
   * Get a base model builder for a certificate to be issued. This model builder is populated with default properties for certificates
   * issued by this CA.
   *
   * @param subject   subject name
   * @param publicKey public key to be certified in the certificate
   * @return {@link CertificateModel}
   * @throws CertificateIssuanceException errors creating certificate model
   *                                      Get the CRL issuer instance for this CA service
   */
  CertificateModelBuilder getCertificateModelBuilder(CertNameModel subject, PublicKey publicKey) throws CertificateIssuanceException;

  /**
   * Issue and register a new certificate based on a certificate model
   *
   * @param certificateModel certificate model
   * @return issued certificate
   * @throws CertificateIssuanceException errors issuing the certificate
   */
  X509CertificateHolder issueCertificate(CertificateModel certificateModel) throws CertificateIssuanceException;

  /**
   * Revoke a certificate issued by the CA service with unspecified reason
   *
   * @param serialNumber   serial number of the issued certificate
   * @param revocationDate revocation time
   * @throws CertificateRevocationException errors revoking the certificate
   */
  void revokeCertificate(BigInteger serialNumber, Date revocationDate) throws CertificateRevocationException;

  /**
   * Revoke a certificate issued by the CA service
   *
   * @param serialNumber   serial number of the issued certificate
   * @param reason         reason code
   * @param revocationDate revocation time
   * @throws CertificateRevocationException errors revoking the certificate
   */
  void revokeCertificate(BigInteger serialNumber, int reason, Date revocationDate) throws CertificateRevocationException;

  /**
   * Publish a new CRL from the CA service
   *
   * @return the newly published CRL or null if no CRL was issued.
   * @throws CertificateRevocationException errors revoking the certificate
   */
  X509CRLHolder publishNewCrl() throws CertificateRevocationException;

  /**
   * Getter for the latest published CRL
   *
   * @return latest published CRL
   */
  X509CRLHolder getCurrentCrl();


  /**
   * Getter for the CA certificate of this service
   *
   * @return CA certificate
   */
  X509CertificateHolder getCaCertificate();

  /**
   * Getter for the CA repository for this CA service
   *
   * @return CA repository
   */
  CARepository getCaRepository();

  /**
   * Getter for the OCSP responder for this CA service
   *
   * @return OCSP responder
   */
  OCSPResponder getOCSPResponder();
}
