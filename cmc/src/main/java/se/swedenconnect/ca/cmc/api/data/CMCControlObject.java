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

package se.swedenconnect.ca.cmc.api.data;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.cmc.BodyPartID;

/**
 * Data class for a CMC control object
 *
 * These are also referred to in CMC as TaggedAttribute in CMC requests and responses
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CMCControlObject {

  /** Unique identifier of the control attribute */
  BodyPartID bodyPartID;
  /** Object Identifier of the control attribute */
  CMCControlObjectID type;
  /** Attribute value */
  Object value;

}
