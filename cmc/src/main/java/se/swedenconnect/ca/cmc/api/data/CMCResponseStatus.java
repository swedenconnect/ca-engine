package se.swedenconnect.ca.cmc.api.data;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.cmc.BodyPartID;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;

import java.util.List;

/**
 * Data class for CMC response status information
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CMCResponseStatus {

  public CMCResponseStatus(CMCStatusType status, List<BodyPartID> bodyPartIDList) {
    this.status = status;
    this.bodyPartIDList = bodyPartIDList;
  }

  /** The major status indicating success or failure */
  private CMCStatusType status;
  /** Detailed failure information as provided by {@link CMCFailType} */
  private CMCFailType failType;
  /** Status message, normally null on success responses */
  private String message;
  /** List of request control message body part ID:s that was processed in the request to obtain the response */
  private List<BodyPartID> bodyPartIDList;

}
