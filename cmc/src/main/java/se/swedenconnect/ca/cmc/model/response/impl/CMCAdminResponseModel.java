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
 * Response model for creating CMC responses for Admin requests
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
