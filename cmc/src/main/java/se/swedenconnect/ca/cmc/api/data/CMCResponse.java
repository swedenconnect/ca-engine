package se.swedenconnect.ca.cmc.api.data;

import lombok.*;
import org.bouncycastle.asn1.cmc.PKIResponse;
import se.swedenconnect.ca.cmc.auth.CMCValidator;
import se.swedenconnect.ca.cmc.model.request.CMCRequestModel;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * Data class for CMC response data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CMCResponse {

  /** The type of request this response is responding to */
  private CMCRequestType cmcRequestType;
  /** the bytes of the CMC Response */
  private byte[] cmcResponseBytes;
  /** the response nonce value */
  private byte[] nonce;
  /** the certificates returned in the response except for the CMS signing certificates */
  private List<X509Certificate> returnCertificates;
  /** The PKIResponse data of the response */
  private PKIResponse pkiResponse;
  /** Response status of the response */
  private CMCResponseStatus responseStatus;
  /** Message time carried in the custom messageTime control attribute */
  private Date messageTime;




}
