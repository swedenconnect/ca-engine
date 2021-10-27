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

package se.swedenconnect.ca.cmc.auth;

import lombok.Getter;

/**
 * Exception thrown during CMC validation
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCValidationException extends RuntimeException {

  @Getter
  CMCValidationResult validationResult;

  public CMCValidationException(CMCValidationResult validationResult) {
    this.validationResult = validationResult;
  }

  public CMCValidationException(String message, CMCValidationResult validationResult) {
    super(message);
    this.validationResult = validationResult;
  }

  public CMCValidationException(String message, Throwable cause, CMCValidationResult validationResult) {
    super(message, cause);
    this.validationResult = validationResult;
  }

  public CMCValidationException(Throwable cause, CMCValidationResult validationResult) {
    super(cause);
    this.validationResult = validationResult;
  }

  public CMCValidationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace,
    CMCValidationResult validationResult) {
    super(message, cause, enableSuppression, writableStackTrace);
    this.validationResult = validationResult;
  }
}
