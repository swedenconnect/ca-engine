package se.swedenconnect.ca.cmc.api.data;

import lombok.*;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CertificationRequest;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CMCRequest {

  private byte[] cmcRequestBytes;
  private byte[] nonce;
  CMCRequestType cmcRequestType;
  CertificationRequest certificationRequest;
  CertificateRequestMessage certificateRequestMessage;
  BodyPartID certReqBodyPartId;
  PKIData pkiData;

}
