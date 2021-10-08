package se.swedenconnect.ca.cmc.model.request.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.Getter;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;

import java.io.IOException;

/**
 * CMC Revocation request model
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public class CMCAdminRequestModel extends AbstractCMCRequestModel {
  public CMCAdminRequestModel(AdminCMCData adminRequestData)
    throws IOException {
    super(CMCRequestType.admin, getReqInfo(adminRequestData));
  }

  private static byte[] getReqInfo(AdminCMCData adminCMCData) throws IOException {
    try {
      return CMCUtils.OBJECT_MAPPER.writeValueAsBytes(adminCMCData);
    }
    catch (JsonProcessingException e) {
      throw new IOException("Unable to convert admin request data to JSON", e);
    }
  }
}
