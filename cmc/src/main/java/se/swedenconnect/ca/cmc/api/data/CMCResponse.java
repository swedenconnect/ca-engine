package se.swedenconnect.ca.cmc.api.data;

import lombok.*;
import org.bouncycastle.asn1.cmc.PKIResponse;
import se.swedenconnect.ca.cmc.auth.CMCValidator;
import se.swedenconnect.ca.cmc.model.request.CMCRequestModel;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

import java.io.IOException;
import java.security.cert.X509Certificate;
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

  CMCRequestType cmcRequestType;
  private byte[] cmcResponseBytes;
  private byte[] nonce;
  List<X509Certificate> returnCertificates;
  PKIResponse pkiResponse;
  CMCResponseStatus responseStatus;




}
