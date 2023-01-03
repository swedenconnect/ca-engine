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

/**
 * Exception thrown as a result of failure to issue a certificate
 *
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CertificateIssuanceException extends IOException {

  /** For serializing. */
  private static final long serialVersionUID = 8463084075292154476L;

  /**
   * Constructor
   *
   * @param message message
   */
  public CertificateIssuanceException(final String message) {
    super(message);
  }

  /**
   * Constructor
   *
   * @param message message
   * @param cause cause
   */
  public CertificateIssuanceException(final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructor
   *
   * @param cause cause
   */
  public CertificateIssuanceException(final Throwable cause) {
    super(cause);
  }

}
