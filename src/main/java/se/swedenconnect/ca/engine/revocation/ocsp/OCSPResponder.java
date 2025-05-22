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
package se.swedenconnect.ca.engine.revocation.ocsp;

import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.cert.ocsp.OCSPResp;

import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;

/**
 * Interface for an OCSP Responder.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface OCSPResponder {

  /**
   * Process a request for certificate status information.
   *
   * @param ocspRequest OCSP request
   * @return OCSP response
   * @throws CertificateRevocationException on exceptions that prevents generation of an OCSP response
   */
  OCSPResp handleRequest(final OCSPRequest ocspRequest) throws CertificateRevocationException;
}
