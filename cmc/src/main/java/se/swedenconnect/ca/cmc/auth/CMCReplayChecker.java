package se.swedenconnect.ca.cmc.auth;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CMCReplayChecker {

  /**
   * Validates if the provided nonce is a valid representation of a new request that was not processed previously
   * @param nonce
   * @return
   */
  boolean isNewRequest(byte[] nonce);

}
