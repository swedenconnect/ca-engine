package se.swedenconnect.ca.cmc.api.data;

import lombok.*;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CertificationRequest;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

import java.util.Date;

/**
 * Data class for CMC request data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CMCRequest {

  /** The bytes of the CMC request */
  private byte[] cmcRequestBytes;
  /** The request nonce */
  private byte[] nonce;
  /** The type of request according to local type declaration */
  private CMCRequestType cmcRequestType;
  /** The PKCS#10 request in this CMC request, if present */
  private CertificationRequest certificationRequest;
  /** The CRMF certificate request in this CMC request, if present */
  private CertificateRequestMessage certificateRequestMessage;
  /** The BodyPartId (or CRMF ID) of the certificate request in this CMC request, if present */
  private BodyPartID certReqBodyPartId;
  /** The PKIData structure of this CMC request */
  private PKIData pkiData;
  /** Message time of this request, if present in the custom control attribute defined here */
  private Date messageTime;

}
