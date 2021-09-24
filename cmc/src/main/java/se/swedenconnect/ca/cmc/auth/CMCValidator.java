package se.swedenconnect.ca.cmc.auth;

import lombok.NoArgsConstructor;

/**
 * Description
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
