package se.swedenconnect.ca.cmc.api;

import se.swedenconnect.ca.cmc.auth.CMCValidator;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCResponseParser {

  private final CMCValidator validator;

  public CMCResponseParser(CMCValidator validator) {
    this.validator = validator;
  }

}
