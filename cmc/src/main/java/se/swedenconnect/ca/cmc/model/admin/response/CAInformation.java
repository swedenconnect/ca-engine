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

package se.swedenconnect.ca.cmc.model.admin.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Data class for information about the CA providing this CMC API
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CAInformation {

  /** The number of issued certificates in the database */
  private int certificateCount;
  /** The number of non revoked certificates in the database */
  private int validCertificateCount;
  /** The CA certificate chain */
  List<byte[]> certificateChain;
  /** The optional OCSP certificate used by the OCSP responder of this CA */
  byte[] ocspCertificate;
  /** The location of the CRL of this CA service */
  List<String> crlDpURLs;
  /** The URL to the OCSP responder of this CA if present */
  String ocspResponserUrl;
  /** The algorithm used by this CA to sign certificates */
  String caAlgorithm;

}
