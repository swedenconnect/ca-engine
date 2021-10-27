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

import lombok.NoArgsConstructor;

/**
 * Interface for a CMC message validator that validates the signature on the CMC message as well
 * as that the originator is authorized to send this request.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CMCValidator {

  /**
   * Validates the signature on a CMC against a defined trust configuration
   * @param cmcMessage the CMC message to validate
   * @return Validation result
   */
  CMCValidationResult validateCMC(byte[] cmcMessage);


}
