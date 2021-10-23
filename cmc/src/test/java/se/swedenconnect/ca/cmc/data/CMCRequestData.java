package se.swedenconnect.ca.cmc.data;

import com.fasterxml.jackson.core.JsonProcessingException;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.admin.AdminRequestType;
import se.swedenconnect.ca.cmc.model.admin.request.ListCerts;
import se.swedenconnect.ca.cmc.utils.TestUtils;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.ca.repository.SortBy;

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

  public static final String USER1 = "def";
  public static final String USER2 = "def";
  public static final String USER3 = "def";
  public static final String LIST_CERTS = "listCerts";
  public static final String CA_INFO = "caInfo";
  public static final String LIST_CERT_SERIALS = "listSerials";

  public static Map<String, CertNameModel> subjectMap;
  public static Map<String, AdminCMCData> adminRequestMap;


  static {
    subjectMap = new HashMap<>();
    subjectMap.put(USER1, new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value("Nisse Hult").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SERIALNUMBER).value("12345678901").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.GIVENNAME).value("Nisse").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SURNAME).value("Hult").build()
    )));
    subjectMap.put(USER2, new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value("User Two").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SERIALNUMBER).value("12345678902").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.GIVENNAME).value("User").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SURNAME).value("Two").build()
    )));
    subjectMap.put(USER3, new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value("User three").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SERIALNUMBER).value("12345678903").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.GIVENNAME).value("User").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SURNAME).value("Three").build()
    )));

    adminRequestMap = new HashMap<>();
    try {
      adminRequestMap.put(LIST_CERTS, AdminCMCData.builder()
          .adminRequestType(AdminRequestType.listCerts)
          .data(TestUtils.OBJECT_MAPPER.writeValueAsString(ListCerts.builder()
              .pageIndex(0)
              .pageSize(10)
              .valid(false)
              .sortBy(SortBy.issueDate)
            .build()))
        .build());
      adminRequestMap.put(CA_INFO, AdminCMCData.builder().adminRequestType(AdminRequestType.caInfo).build());
      adminRequestMap.put(LIST_CERT_SERIALS, AdminCMCData.builder().adminRequestType(AdminRequestType.allCertSerials).build());

    }
    catch (JsonProcessingException e) {
      e.printStackTrace();
    }

  }



}
