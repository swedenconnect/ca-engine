package se.swedenconnect.ca.cmc.data;

import lombok.AllArgsConstructor;
import lombok.Getter;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
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

  CMCResponseStatus responseStatus;

}
