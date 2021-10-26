package se.swedenconnect.ca.cmc.api;

import lombok.Getter;
import org.bouncycastle.asn1.cmc.BodyPartID;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCCaApiException extends IOException {

  @Getter private final List<BodyPartID> failingBodyPartIds;
  @Getter private final CMCFailType cmcFailType;

  public CMCCaApiException(List<BodyPartID> failingBodyPartIds, CMCFailType cmcFailType) {
    this.failingBodyPartIds = failingBodyPartIds;
    this.cmcFailType = cmcFailType;
  }

  public CMCCaApiException(String message, List<BodyPartID> failingBodyPartIds, CMCFailType cmcFailType) {
    super(message);
    this.failingBodyPartIds = failingBodyPartIds;
    this.cmcFailType = cmcFailType;
  }

  public CMCCaApiException(String message, Throwable cause, BodyPartID failingBodyPartId) {
    super(message, cause);
    this.failingBodyPartIds = Arrays.asList(failingBodyPartId);
    this.cmcFailType = CMCFailType.badRequest;
  }

  public CMCCaApiException(String message, Throwable cause, BodyPartID failingBodyPartId,
    CMCFailType cmcFailType) {
    super(message, cause);
    this.failingBodyPartIds = Arrays.asList(failingBodyPartId);
    this.cmcFailType = cmcFailType;
  }

  public CMCCaApiException(String message, Throwable cause, List<BodyPartID> failingBodyPartIds,
    CMCFailType cmcFailType) {
    super(message, cause);
    this.failingBodyPartIds = failingBodyPartIds;
    this.cmcFailType = cmcFailType;
  }

  public CMCCaApiException(Throwable cause, List<BodyPartID> failingBodyPartIds, CMCFailType cmcFailType) {
    super(cause);
    this.failingBodyPartIds = failingBodyPartIds;
    this.cmcFailType = cmcFailType;
  }
}
