package se.swedenconnect.ca.cmc.model.response.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.Getter;
import org.bouncycastle.asn1.cmc.BodyPartID;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

import java.io.IOException;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCAdminResponseModel extends AbstractCMCResponseModel {

  @Getter private AdminCMCData adminCMCData;

  public CMCAdminResponseModel(byte[] nonce, CMCResponseStatus cmcResponseStatus, CMCRequestType cmcRequestType, AdminCMCData adminCMCData) throws IOException {
    super(nonce, cmcResponseStatus, cmcRequestType, getResponseInfo(adminCMCData));
    this.adminCMCData = adminCMCData;
  }

  private static byte[] getResponseInfo(AdminCMCData adminCMCData) throws IOException {
    try {
      return CMCUtils.OBJECT_MAPPER.writeValueAsBytes(adminCMCData);
    }
    catch (JsonProcessingException e) {
      throw new IOException("Unable to convert admin request data to JSON", e);
    }
  }

}
