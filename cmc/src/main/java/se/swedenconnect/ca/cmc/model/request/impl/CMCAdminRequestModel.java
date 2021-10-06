package se.swedenconnect.ca.cmc.model.request.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.Getter;
import org.bouncycastle.operator.ContentSigner;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.cmc.model.request.admin.AdminRequestData;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * CMC Revocation request model
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public class CMCAdminRequestModel extends AbstractCMCRequestModel {
  public CMCAdminRequestModel(AdminRequestData adminRequestData, ContentSigner cmcSigner, List<X509Certificate> cmcSignerCerts)
    throws IOException {
    super(CMCRequestType.admin, cmcSigner, cmcSignerCerts, getReqInfo(adminRequestData));
  }

  private static byte[] getReqInfo(AdminRequestData adminRequestData) throws IOException {
    try {
      return CMCUtils.OBJECT_MAPPER.writeValueAsBytes(adminRequestData);
    }
    catch (JsonProcessingException e) {
      throw new IOException("Unable to convert admin request data to JSON", e);
    }
  }
}
