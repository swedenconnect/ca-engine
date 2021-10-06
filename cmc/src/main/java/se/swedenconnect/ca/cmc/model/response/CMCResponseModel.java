package se.swedenconnect.ca.cmc.model.response;

import org.bouncycastle.operator.ContentSigner;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CMCResponseModel {

  /**
   * Gets the request nonce
   * @return request nonce
   */
  byte[] getNonce();

  /**
   * Gets the registration info data. Each request type identifies the syntax of this parameter
   * @return registration info data
   */
  byte[] getResponseInfo();

  /**
   * The type of request
   * @return cmc request type
   */
  CMCRequestType getCmcRequestType();

  /**
   * Get the signer of the CMC message
   * @return signer
   */
  ContentSigner getCmcSigner();

  /**
   * Get the signer certificate chain of the CMC signer
   * @return CMC signer certificates
   */
  List<X509Certificate> getCmcSignerCerts();
}
