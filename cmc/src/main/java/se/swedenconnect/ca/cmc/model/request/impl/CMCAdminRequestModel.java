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
