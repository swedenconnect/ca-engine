package se.swedenconnect.ca.cmc.api.client;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import se.swedenconnect.ca.cmc.api.data.CMCControlObject;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.admin.AdminRequestType;
import se.swedenconnect.ca.cmc.model.admin.response.CAInformation;
import se.swedenconnect.ca.cmc.model.admin.response.CertificateData;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

import java.io.IOException;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCResponseExtract {

  public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  public static AdminCMCData getAdminCMCData (CMCResponse cmcResponse) throws IOException {
    if (!cmcResponse.getCmcRequestType().equals(CMCRequestType.admin)){
      throw new IOException("Not an admin response");
    }
    final CMCControlObject cmcControlObject = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_responseInfo, cmcResponse.getPkiResponse());
    AdminCMCData adminCMCData = (AdminCMCData) cmcControlObject.getValue();
    return adminCMCData;
  }

  public static List<CertificateData> extractCertificateData(CMCResponse cmcResponse) throws IOException {
    final AdminCMCData adminCMCData = getAdminCMCData(cmcResponse);
    if (!adminCMCData.getAdminRequestType().equals(AdminRequestType.listCerts)){
      throw new IOException("Not a list certificates response");
    }
    List<CertificateData> certificateDataList = OBJECT_MAPPER.readValue(adminCMCData.getData(), new TypeReference<>() {});
    return certificateDataList;
  }

  public static CAInformation extractCAInformation(CMCResponse cmcResponse) throws IOException {
    final AdminCMCData adminCMCData = getAdminCMCData(cmcResponse);
    if (!adminCMCData.getAdminRequestType().equals(AdminRequestType.caInfo)){
      throw new IOException("Not a CA information response");
    }
    CAInformation caInformation = OBJECT_MAPPER.readValue(adminCMCData.getData(), CAInformation.class);
    return caInformation;
  }

}
