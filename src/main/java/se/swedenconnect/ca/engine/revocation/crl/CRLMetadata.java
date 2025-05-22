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

package se.swedenconnect.ca.engine.revocation.crl;

import java.math.BigInteger;
import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Metadata for the most recent CRL issued by any of the instances serving the same CA identity.
 * This takes into account a deployment scenario where multiple instances of the same CA
 * cooperates to provide a unified revocation experience where these data are synchronized and
 * shared among the instances.
 *
 * The data provided here reflects the latest CRL update made by any instance and allows
 * other instances to choose to issue a CRL with identical metadata or to opt for issuance
 * of a new CRL and thus also update and share an updated version of this metadata, allowing
 * other instances to follow.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CRLMetadata {

  /** CRL number of the latest published CRL */
  BigInteger crlNumber;

  /** Issue time of the latest published CRL */
  Instant issueTime;

  /** Next update time of the latest published CRL */
  Instant nextUpdate;

  /** Revoked certificate count of the latest published CRL */
  int revokedCertCount;

}
