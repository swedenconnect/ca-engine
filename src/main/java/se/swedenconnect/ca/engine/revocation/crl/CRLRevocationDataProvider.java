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

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

import org.bouncycastle.cert.X509CRLHolder;

/**
 * CRL revocation data provider interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CRLRevocationDataProvider {

  /**
   * Get revoked certificates
   *
   * @return revoked certificates
   */
  List<RevokedCertificate> getRevokedCertificates();

  /**
   * Get CRL number for the next CRL
   *
   * @return CRL number
   */
  BigInteger getNextCrlNumber();

  /**
   * Publish a new CRL
   *
   * @param crl CRL to publish
   * @throws IOException error publishing the new CLR
   */
  void publishNewCrl(final X509CRLHolder crl) throws IOException;

  /**
   * Getter for the latest published CRL
   *
   * @return latest published CRL or null if no CRL is available
   */
  X509CRLHolder getCurrentCrl();

}
