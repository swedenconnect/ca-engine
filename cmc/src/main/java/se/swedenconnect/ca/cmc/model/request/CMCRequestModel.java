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

package se.swedenconnect.ca.cmc.model.request;

import org.bouncycastle.operator.ContentSigner;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface for the CMC Request model
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CMCRequestModel {

  /**
   * Gets the request nonce
   * @return request nonce
   */
  byte[] getNonce();

  /**
   * Gets the registration info data. Each request type identifies the syntax of this parameter
   * @return registration info data
   */
  byte[] getRegistrationInfo();

  /**
   * The type of request
   * @return cmc request type
   */
  CMCRequestType getCmcRequestType();

}
