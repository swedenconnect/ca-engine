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

package se.swedenconnect.ca.cmc.api;

import lombok.Getter;
import org.bouncycastle.asn1.cmc.BodyPartID;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;

import java.io.IOException;
import java.util.List;

/**
 * Exception used within the CMC CA API.
 *
 * This Exception provides information about the CMC failure code as well as a list of body part IDs of CMC objects that caused the failure
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCCaApiException extends IOException {

  /** List of BodyPartID of CMC objects that was processed when the failure occurred */
  @Getter private final List<BodyPartID> failingBodyPartIds;
  /** CMC failure type */
  @Getter private final CMCFailType cmcFailType;

  public CMCCaApiException(String message, List<BodyPartID> failingBodyPartIds, CMCFailType cmcFailType) {
    super(message);
    this.failingBodyPartIds = failingBodyPartIds;
    this.cmcFailType = cmcFailType;
  }

  public CMCCaApiException(String message, Throwable cause, List<BodyPartID> failingBodyPartIds,
    CMCFailType cmcFailType) {
    super(message, cause);
    this.failingBodyPartIds = failingBodyPartIds;
    this.cmcFailType = cmcFailType;
  }

  public CMCCaApiException(Throwable cause, List<BodyPartID> failingBodyPartIds, CMCFailType cmcFailType) {
    super(cause);
    this.failingBodyPartIds = failingBodyPartIds;
    this.cmcFailType = cmcFailType;
  }
}
