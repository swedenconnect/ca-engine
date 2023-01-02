/*
 * Copyright 2021-2023 Agency for Digital Government (DIGG)
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

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;

/**
 * Interface for a CA service.
 * <p>
 * The CA service provides the collective core services of a CA including certificate issuance and revocation.
 * </p>
 * <p>
 * This interface is not necessary to provide a CA service, but it can be a convenient collection point that
 * consolidates all the parts of the CA service and its core functions.
 * </p>
 *
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CAService {

  /**
   * Get a base model builder for a certificate to be issued. This model builder is populated with default properties
   * for certificates issued by this CA.
   *
   * @param subject subject name
   * @param publicKey public key to be certified in the certificate
   * @return CertificateModel
   * @throws CertificateIssuanceException errors creating certificate model Get the CRL issuer instance for this CA
   *           service
   */
  CertificateModelBuilder getCertificateModelBuilder(final CertNameModel<?> subject, final PublicKey publicKey)
      throws CertificateIssuanceException;

  /**
   * Issue and register a new certificate based on a certificate model
   *
   * @param certificateModel certificate model
   * @return issued certificate
   * @throws CertificateIssuanceException errors issuing the certificate
   */
  X509CertificateHolder issueCertificate(final CertificateModel certificateModel) throws CertificateIssuanceException;

  /**
   * Revoke a certificate issued by the CA service with unspecified reason
   *
   * @param serialNumber serial number of the issued certificate
   * @param revocationDate revocation time
   * @throws CertificateRevocationException errors revoking the certificate
   */
  void revokeCertificate(final BigInteger serialNumber, final Date revocationDate)
      throws CertificateRevocationException;

  /**
   * Revoke a certificate issued by the CA service. The revocation request MUST be rejected if the specified serial
   * number does not exist or if the certificate with this serial number has already been revoked with a reason other
   * than certificate hold
   *
   * @param serialNumber serial number of the issued certificate
   * @param reason reason code
   * @param revocationDate revocation time
   * @throws CertificateRevocationException errors revoking the certificate
   */
  void revokeCertificate(final BigInteger serialNumber, final int reason, final Date revocationDate)
      throws CertificateRevocationException;

  /**
   * Publish a new CRL from the CA service
   *
   * @return the newly published CRL or null if no CRL was issued.
   * @throws CertificateRevocationException errors revoking the certificate
   */
  X509CRLHolder publishNewCrl() throws IOException;

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
   * Returns the current configured certificate chain to a trusted root
   *
   * @return CA certificate chain with the CA certificate first and the trust anchor last in the list
   */
  List<X509CertificateHolder> getCACertificateChain();

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

  /**
   * Getter for the OCSP responder certificate
   *
   * @return OCSP responder certificate or null of the CA has no OCSP responder
   */
  X509CertificateHolder getOCSPResponderCertificate();

  /**
   * Getter for the URI identifier of the algorithm used by the CA to sign certificates
   *
   * @return CA signing algorithm URI identifier
   */
  String getCaAlgorithm();

  /**
   * Getter for the CRL distribution point URLs of this CA
   *
   * @return List of CRL distribution point URL
   */
  List<String> getCrlDpURLs();

  /**
   * The OCSP responder URL for this CA, if present
   *
   * @return OCSP responder URL
   */
  String getOCSPResponderURL();

}
