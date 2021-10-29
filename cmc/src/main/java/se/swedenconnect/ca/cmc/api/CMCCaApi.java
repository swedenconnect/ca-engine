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

import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;

import java.io.IOException;
import java.security.cert.CertificateException;

/**
 * The main interface for the CMC API
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CMCCaApi {

  /**
   * Process a CMC Request in the context of a CA service. This function shall never throw an exception caused by
   * errors in the request. Any such error condition is captured in an error response with appropriate error code
   * and a suitable error message.
   *
   * @param cmcRequestBytes the CMC request providing a request for service
   * @return a CMC response providing the status and result data as a result of the service request
   */
  CMCResponse processRequest (byte[] cmcRequestBytes);

}
