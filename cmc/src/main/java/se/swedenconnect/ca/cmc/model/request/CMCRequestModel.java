package se.swedenconnect.ca.cmc.model.request;

import org.bouncycastle.operator.ContentSigner;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CMCRequestModel {

  /**
   * Gets the request nonce
   * @return request nonce
   */
  byte[] getNonce();

  /**
   * Gets the registration info data. Each request type identifies the syntax of this parameter
   * @return registration info data
   */
  byte[] getRegistrationInfo();

  /**
   * The type of request
   * @return cmc request type
   */
  CMCRequestType getCmcRequestType();

}
