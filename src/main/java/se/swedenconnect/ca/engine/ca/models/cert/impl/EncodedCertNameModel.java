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
package se.swedenconnect.ca.engine.ca.models.cert.impl;

import org.bouncycastle.asn1.x500.X500Name;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;

/**
 * Holds the X500 name used primary as Certificate Issuer or Subject name
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class EncodedCertNameModel implements CertNameModel<X500Name> {

  private X500Name x500Name;

  @Override
  public CertNameModelType getType() {
    return CertNameModelType.encoded;
  }

  @Override
  public X500Name getNameData() {
    return x500Name;
  }
}
