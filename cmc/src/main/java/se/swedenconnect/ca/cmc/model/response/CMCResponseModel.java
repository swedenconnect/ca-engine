package se.swedenconnect.ca.cmc.model.response;

import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
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
   * The status of the response
   * @return cmc response status
   */
  CMCResponseStatus getCmcResponseStatus();

  /**
   * Return certificates for the response
   * @return list of certificate bytes
   */
  List<X509Certificate> getReturnCertificates();

}
