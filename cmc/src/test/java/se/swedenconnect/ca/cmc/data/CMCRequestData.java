/*
 * Copyright (c) 2021. Agency for Digital Government (DIGG)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

  public static final String USER1 = "User1";
  public static final String USER2 = "User2";
  public static final String USER3 = "User3";
  public static final String PKCS10_USER = "User4";
  public static final String CRMF_USER = "User5";
  public static final String LIST_CERTS = "listCerts";
  public static final String CA_INFO = "caInfo";
  public static final String LIST_CERT_SERIALS = "listSerials";

  public static Map<String, CertNameModel> subjectMap;
  public static Map<String, AdminCMCData> adminRequestMap;


  static {
    subjectMap = new HashMap<>();
    subjectMap.put(USER1, new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value("Test User One").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SERIALNUMBER).value("12345678901").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.GIVENNAME).value("Test User").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SURNAME).value("One").build()
    )));
    subjectMap.put(USER2, new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value("Test User Two").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SERIALNUMBER).value("12345678902").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.GIVENNAME).value("Test User").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SURNAME).value("Two").build()
    )));
    subjectMap.put(USER3, new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value("Test User Three").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SERIALNUMBER).value("12345678903").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.GIVENNAME).value("Test User").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SURNAME).value("Three").build()
    )));
    subjectMap.put(PKCS10_USER, new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value("PKCS10 User Four").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SERIALNUMBER).value("12345678903").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.GIVENNAME).value("PKCS10 User").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SURNAME).value("Four").build()
    )));
    subjectMap.put(CRMF_USER, new ExplicitCertNameModel(Arrays.asList(
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value("CRMF User Five").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SERIALNUMBER).value("12345678903").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.GIVENNAME).value("CRMF User").build(),
      AttributeTypeAndValueModel.builder().attributeType(CertAttributes.SURNAME).value("Five").build()
    )));

    adminRequestMap = new HashMap<>();
    try {
      adminRequestMap.put(LIST_CERTS, AdminCMCData.builder()
          .adminRequestType(AdminRequestType.listCerts)
          .data(TestUtils.OBJECT_MAPPER.writeValueAsString(ListCerts.builder()
              .pageIndex(0)
              .pageSize(10)
              .notRevoked(false)
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
