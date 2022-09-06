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
package se.swedenconnect.ca.engine.revocation.crl;

import org.bouncycastle.cert.X509CRLHolder;

import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;

/**
 * CRL Issuer interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CRLIssuer {

  /**
   * Issue a CRL for revoked certificates.
   *
   * @return Issued CRL
   * @throws CertificateRevocationException errors creating the CRL
   */
  X509CRLHolder issueCRL() throws CertificateRevocationException;
}
