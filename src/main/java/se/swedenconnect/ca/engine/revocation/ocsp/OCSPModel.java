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
package se.swedenconnect.ca.engine.revocation.ocsp;

import java.time.Duration;

import org.bouncycastle.cert.X509CertificateHolder;

import lombok.Getter;
import lombok.Setter;

/**
 * OCSP model holding OCSP service configuration data.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public class OCSPModel {

  /** Certificate of the issuer of certificates being checked by this OCSP responder */
  private final X509CertificateHolder certificateIssuerCert;

  /** Signature algorithm for signing OCSP responses */
  private final String algorithm;

  /** Offset duration for altering response this update time relative to current time */
  @Setter
  private Duration startOffset = Duration.ofSeconds(-30);

  /**
   * Time duration for specifying the next update time in OCSP responses. a null value indicates an absent next update
   * time in the response.
   */
  @Setter
  private Duration expiryOffset = null;

  /**
   * Constructor for OCSP model.
   *
   * @param certificateIssuerCert the certificate of the CA that issues certificates that this service provides status
   *          for
   * @param algorithm OCSP response signing algorithm
   */
  public OCSPModel(final X509CertificateHolder certificateIssuerCert, final String algorithm) {
    this.algorithm = algorithm;
    this.certificateIssuerCert = certificateIssuerCert;
  }

}
