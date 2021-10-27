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

package se.swedenconnect.ca.cmc.auth;

import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.cms.CMSSignedData;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;

import java.io.IOException;
import java.util.Date;

/**
 * Interface for implementation of a replay checker used by the CMC parser to determine if a CMC request is new and not
 * a replay of an old request.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CMCReplayChecker {

  /**
   * Validates a CMC request against replay according to a defined policy
   * @param nonce the nonce of the CMC request to validate
   * @param signingTime The signing time collected from the CMS signature signed attributes (1.2.840.113549.1.9.5)
   * @throws IOException if a violation of the replay protection policy is detected
   */
  void validate(CMSSignedData cmsSignedData) throws IOException;

}
