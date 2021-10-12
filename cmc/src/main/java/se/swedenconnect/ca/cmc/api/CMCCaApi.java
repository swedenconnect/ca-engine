package se.swedenconnect.ca.cmc.api;

import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;

import java.io.IOException;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CMCCaApi {

  CMCResponse processRequest (CMCRequest cmcRequest) throws RuntimeException;

}
