package se.swedenconnect.ca.cmc.auth;

import org.bouncycastle.asn1.cmc.PKIData;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;

import java.io.IOException;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CMCReplayChecker {

  /**
   * Validates if the provided cmcRequest is a valid representation of a new request that was not a replay of an old request
   * or an outdated request for which replay detection is not possible.
   * @param pkiData The signed content of a CMC request to check
   * @return true if the request is recent and not a replay of a previously processed request.
   */

  /**
   * Validates a CMC request against replay according to a defined policy
   * @param pkiData The signed content of a CMC request to validate
   * @throws IOException if a violation of the replay protection policy is detected
   */
  void validate(PKIData pkiData) throws IOException;

}
