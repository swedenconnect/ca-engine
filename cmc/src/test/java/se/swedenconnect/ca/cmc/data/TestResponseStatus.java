package se.swedenconnect.ca.cmc.data;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.asn1.cmc.BodyPartID;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;

import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@AllArgsConstructor
public enum TestResponseStatus {

  success(CMCResponseStatus.builder()
    .status(CMCStatusType.success)
    .build()),
  failBadRequest(CMCResponseStatus.builder()
    .status(CMCStatusType.failed)
    .failType(CMCFailType.badRequest)
    .message("Bad CMC Request")
    .build());

  private CMCResponseStatus responseStatus;

  public CMCResponseStatus withBodyParts(List<BodyPartID> bodyPartIDList){
    CMCResponseStatus status = CMCResponseStatus.builder()
      .status(responseStatus.getStatus())
      .failType(responseStatus.getFailType())
      .message(responseStatus.getMessage())
      .bodyPartIDList(bodyPartIDList)
      .build();
    return status;
  }

}
