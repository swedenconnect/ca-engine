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

package se.swedenconnect.ca.engine.revocation;

/**
 * Exception class for certificate revocation.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CertificateRevocationException extends RuntimeException {

  private static final long serialVersionUID = -2229186707266267663L;

  /**
   * Constructor
   */
  public CertificateRevocationException() {
  }

  /**
   * Constructor
   *
   * @param message message
   */
  public CertificateRevocationException(final String message) {
    super(message);
  }

  /**
   * Constructor
   *
   * @param message message
   * @param cause cause
   */
  public CertificateRevocationException(final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructor
   *
   * @param cause cause
   */
  public CertificateRevocationException(final Throwable cause) {
    super(cause);
  }

  /**
   * Constructor
   *
   * @param message message
   * @param cause cause
   * @param enableSuppression enable suppression
   * @param writableStackTrace writable stack trace
   */
  public CertificateRevocationException(final String message, final Throwable cause, final boolean enableSuppression,
      final boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
