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
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;

/**
 * Exception thrown when determining the status of a requested certificate in a OCSP request.
 * The response status passed in the request is stored in the exception.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class OCSPStatusCheckingException extends CertificateRevocationException {

  /** The response status that should be returned in the OCSP response */
  @Getter final int responseStatus;

  /**
   * Constructor
   *
   * @param responseStatus response status
   */
  public OCSPStatusCheckingException(int responseStatus) {
    this.responseStatus = responseStatus;
  }

  /**
   * Constructor
   *
   * @param message message
   * @param responseStatus response status
   */
  public OCSPStatusCheckingException(String message, int responseStatus) {
    super(message);
    this.responseStatus = responseStatus;
  }

  /**
   * Constructor
   *
   * @param message message
   * @param cause cause
   * @param responseStatus response status
   */
  public OCSPStatusCheckingException(String message, Throwable cause, int responseStatus) {
    super(message, cause);
    this.responseStatus = responseStatus;
  }

  /**
   * Constructor
   *
   * @param cause cause
   * @param responseStatus response status
   */
  public OCSPStatusCheckingException(Throwable cause, int responseStatus) {
    super(cause);
    this.responseStatus = responseStatus;
  }

  /**
   * Constructor
   *
   * @param message message
   * @param cause cause
   * @param enableSuppression enable suppression
   * @param writableStackTrace writable stack trace
   * @param responseStatus response status
   */
  public OCSPStatusCheckingException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace,
    int responseStatus) {
    super(message, cause, enableSuppression, writableStackTrace);
    this.responseStatus = responseStatus;
  }
}
