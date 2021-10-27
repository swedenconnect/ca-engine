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

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.asn1.cmc.BodyPartID;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.cmc.model.response.CMCResponseModel;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Abstract implementation of the CMC response model
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AbstractCMCResponseModel implements CMCResponseModel {

  public AbstractCMCResponseModel(byte[] nonce, CMCResponseStatus cmcResponseStatus, CMCRequestType cmcRequestType) {
    this(nonce, cmcResponseStatus, cmcRequestType,  null);
  }

  public AbstractCMCResponseModel(byte[] nonce, CMCResponseStatus cmcResponseStatus, CMCRequestType cmcRequestType, byte[] responseInfo) {
    this.nonce = nonce;
    this.responseInfo = responseInfo;
    this.cmcResponseStatus = cmcResponseStatus;
    this.returnCertificates = new ArrayList<>();
    this.cmcRequestType = cmcRequestType;
  }

  @Getter @Setter protected byte[] nonce;
  @Getter @Setter protected byte[] responseInfo;
  @Getter @Setter protected List<X509Certificate> returnCertificates;
  @Getter protected CMCResponseStatus cmcResponseStatus;
  @Getter protected CMCRequestType cmcRequestType;
}
