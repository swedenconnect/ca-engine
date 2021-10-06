package se.swedenconnect.ca.cmc.data;

import com.fasterxml.jackson.core.JsonProcessingException;
import se.swedenconnect.ca.cmc.api.CMCRequest;
import se.swedenconnect.ca.cmc.model.admin.AdminRequestData;
import se.swedenconnect.ca.cmc.model.admin.AdminRequestType;
import se.swedenconnect.ca.cmc.model.admin.ListCerts;
import se.swedenconnect.ca.cmc.model.admin.SortBy;
import se.swedenconnect.ca.cmc.model.impl.CMCAdminRequestModel;
import se.swedenconnect.ca.cmc.utils.TestUtils;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCRequestData {

  public static final String DEFAULT = "def";
  public static final String LIST_CERTS = "listCerts";
  public static final String CA_INFO = "caInfo";
  public static final String LIST_CERT_SERIALS = "listSerials";

  public static Map<String, CertNameModel> subjectMap;
  public static Map<String, AdminRequestData> adminRequestMap;


  static {
    subjectMap = new HashMap<>();
    subjectMap.put(DEFAULT, new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value("Nisse Hult").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SERIALNUMBER).value("1234567890").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.GIVENNAME).value("Nisse").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SURNAME).value("Hult").build()
    )));

    adminRequestMap = new HashMap<>();
    try {
      adminRequestMap.put(LIST_CERTS, AdminRequestData.builder()
          .adminRequestType(AdminRequestType.listCerts)
          .requestData(TestUtils.OBJECT_MAPPER.writeValueAsString(ListCerts.builder()
              .pageIndex(0)
              .pageSize(10)
              .valid(false)
              .sortBy(SortBy.issueDate)
            .build()))
        .build());
      adminRequestMap.put(CA_INFO, AdminRequestData.builder().adminRequestType(AdminRequestType.caInfo).build());
      adminRequestMap.put(LIST_CERT_SERIALS, AdminRequestData.builder().adminRequestType(AdminRequestType.allCertSerials).build());

    }
    catch (JsonProcessingException e) {
      e.printStackTrace();
    }

  }



}
