package se.swedenconnect.ca.cmc.auth;

import lombok.Getter;

/**
 * Description
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
