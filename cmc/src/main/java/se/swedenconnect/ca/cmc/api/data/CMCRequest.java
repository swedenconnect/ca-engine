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

import lombok.*;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CertificationRequest;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

import java.util.Date;

/**
 * Data class for CMC request data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CMCRequest {

  /** The bytes of the CMC request */
  private byte[] cmcRequestBytes;
  /** The request nonce */
  private byte[] nonce;
  /** The type of request according to local type declaration */
  private CMCRequestType cmcRequestType;
  /** The PKCS#10 request in this CMC request, if present */
  private CertificationRequest certificationRequest;
  /** The CRMF certificate request in this CMC request, if present */
  private CertificateRequestMessage certificateRequestMessage;
  /** The BodyPartId (or CRMF ID) of the certificate request in this CMC request, if present */
  private BodyPartID certReqBodyPartId;
  /** The PKIData structure of this CMC request */
  private PKIData pkiData;

}
