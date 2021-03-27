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

package se.swedenconnect.ca.engine.ca.models.cert.extension;

import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;

/**
 * Interface of certificate extension model
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface ExtensionModel {

  /**
   * Adds an extension based on this extension model to the certificate to be signed
   *
   * @param certificateBuilder builder for the certificate to be signed
   * @throws CertificateIssuanceException error building the intended extension based on the extension model
   */
  void addExtensions(JcaX509v3CertificateBuilder certificateBuilder) throws CertificateIssuanceException;

}
