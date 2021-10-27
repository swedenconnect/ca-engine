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

import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;

/**
 * Enumeration of CMC request types
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public enum CMCRequestType {
  /** A request to issue a certificate */
  issueCert,
  /** A request to revoke a certificate */
  revoke,
  /** A custom Admin request using the {@link AdminCMCData} to further specify the type of admin request*/
  admin,
  /** A request to get a particular certificate from the CA database based on the serial number of the certificate */
  getCert
}
