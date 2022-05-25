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

package se.swedenconnect.ca.engine.revocation.ocsp;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.cert.X509CertificateHolder;

import java.util.Calendar;
import java.util.List;

/**
 * OCSP model holding OCSP service configuration data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public class OCSPModel {

  /** OCSP responder certificate chain */
  private final List<X509CertificateHolder> responderCertificateCahin;
  /** Certificate of the issuer of certificates being checked by this OCSP responder */
  private final X509CertificateHolder certificateIssuerCert;
  /** Signature algorithm for signing OCSP responses */
  private final String algorithm;
  /** Offset type for altering response this update time relative to current time */
  @Setter private int startOffsetType = Calendar.SECOND;
  /** Offset amount for altering response this update time relative to current time */
  @Setter private int startOffsetAmount = -30;
  /** Time type for specifying the next update time in OCSP responses */
  @Setter private int expiryOffsetType = Calendar.HOUR;
  /** Time amount of specified type for the next update time where 0 indicates an absent next update time in the response */
  @Setter private int expiryOffsetAmount = 0;

  /**
   * Constructor for OCSP model
   *
   * @param responderCertificateChain certificate chain for the OCSP responder issuing key
   * @param certificateIssuerCert the certificate of the CA that issues certificates that this service provides status for
   * @param algorithm OCSP response signing algorithm
   */
  public OCSPModel(List<X509CertificateHolder> responderCertificateChain, X509CertificateHolder certificateIssuerCert, String algorithm) {
    this.responderCertificateCahin = responderCertificateChain;
    this.algorithm = algorithm;
    this.certificateIssuerCert = certificateIssuerCert;
  }
}
