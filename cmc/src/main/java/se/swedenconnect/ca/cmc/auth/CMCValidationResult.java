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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Data class holding CMC validation data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CMCValidationResult {

  /** Indicates if the CMC message is valid and originates from an authorized source */
  private boolean valid;
  /** Indicates if the response is a simple response */
  private boolean simpleResponse;
  /** Holding the signed data structure of the CMC message */
  private CMSSignedData signedData;
  /** The content type of the CMS signature */
  private ASN1ObjectIdentifier contentType;
  /** The validated certificate path */
  private List<X509CertificateHolder> signerCertificatePath;
  /** Optional exception thrown during validation */
  private Exception exception;
  /** Optional error message */
  private String errorMessage;

}
