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
 * Description
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

  private CMCStatusType status;
  private CMCFailType failType;
  private String message;
  private List<BodyPartID> bodyPartIDList;

}
