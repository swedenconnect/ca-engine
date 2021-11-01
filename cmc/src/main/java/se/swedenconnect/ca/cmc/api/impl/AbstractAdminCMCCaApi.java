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

package se.swedenconnect.ca.cmc.api.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import se.swedenconnect.ca.cmc.api.CMCRequestParser;
import se.swedenconnect.ca.cmc.api.CMCResponseFactory;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.admin.AdminRequestType;
import se.swedenconnect.ca.cmc.model.admin.request.ListCerts;
import se.swedenconnect.ca.cmc.model.admin.response.CAInformation;
import se.swedenconnect.ca.cmc.model.admin.response.CertificateData;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * The default admin implementation of the CMC CA API
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractAdminCMCCaApi extends AbstractCMCCaApi {
  public AbstractAdminCMCCaApi(CAService caService,
    CMCRequestParser cmcRequestParser, CMCResponseFactory cmcResponseFactory) {
    super(caService, cmcRequestParser, cmcResponseFactory);
  }

  @Override protected AdminCMCData getAdminResponse(AdminCMCData adminRequest) throws Exception {

    AdminRequestType adminRequestType = adminRequest.getAdminRequestType();
    String responseInfo = null;

    switch (adminRequestType) {
    case caInfo:
      responseInfo = getCAinfoResponse();
      break;
    case listCerts:
      ListCerts listCertsReqeust = CMCUtils.OBJECT_MAPPER.readValue(adminRequest.getData(), ListCerts.class);
      responseInfo = getListCertsResponse(listCertsReqeust);
      break;
    case allCertSerials:
      responseInfo = getAllCertSerials();
      break;
    }

    return AdminCMCData.builder()
      .adminRequestType(adminRequestType)
      .data(responseInfo)
      .build();
  }

  private String getAllCertSerials() throws JsonProcessingException {
    List<BigInteger> allCertificates = caService.getCaRepository().getAllCertificates();
    List<String> allCertSerialStrings = allCertificates.stream()
      .map(bigInteger -> bigInteger.toString(16))
      .collect(Collectors.toList());
    return CMCUtils.OBJECT_MAPPER.writeValueAsString(allCertSerialStrings);
  }

  private String getListCertsResponse(ListCerts listCertsReqeust) throws JsonProcessingException {
    CARepository caRepository = caService.getCaRepository();
    List<CertificateRecord> certificateRange = caRepository.getCertificateRange(
      listCertsReqeust.getPageIndex(),
      listCertsReqeust.getPageSize(),
      listCertsReqeust.isNotRevoked(),
      listCertsReqeust.getSortBy()
    );

    List<CertificateData> certificateDataList = new ArrayList<>();
    for (CertificateRecord certificateRecord : certificateRange) {
      CertificateData.CertificateDataBuilder builder = CertificateData.builder()
        .certificate(certificateRecord.getCertificate())
        .revoked(certificateRecord.isRevoked());

      if (certificateRecord.isRevoked()) {
        builder
          .revocationReason(certificateRecord.getReason())
          .revocationDate(certificateRecord.getRevocationTime().getTime());
      }
      certificateDataList.add(builder.build());
    }
    return CMCUtils.OBJECT_MAPPER.writeValueAsString(certificateDataList);
  }

  private String getCAinfoResponse() throws Exception {
    CARepository caRepository = caService.getCaRepository();
    CAInformation caInformation = CAInformation.builder()
      .validCertificateCount(caRepository.getCertificateCount(true))
      .certificateCount(caRepository.getCertificateCount(false))
      .certificateChain(CMCUtils.getCerHolderByteList(caService.getCACertificateChain()))
      .ocspCertificate(caService.getOCSPResponderCertificate() != null
        ? caService.getOCSPResponderCertificate().getEncoded()
        : null)
      .caAlgorithm(caService.getCaAlgorithm())
      .ocspResponserUrl(caService.getOCSPResponderURL())
      .crlDpURLs(caService.getCrlDpURLs())
      .build();
    return CMCUtils.OBJECT_MAPPER.writeValueAsString(caInformation);
  }
}
