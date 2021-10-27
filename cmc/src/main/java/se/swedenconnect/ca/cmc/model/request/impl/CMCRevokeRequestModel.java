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

package se.swedenconnect.ca.cmc.model.request.impl;

import lombok.Getter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * CMC Revocation request model
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public class CMCRevokeRequestModel extends AbstractCMCRequestModel {
  public CMCRevokeRequestModel(BigInteger serialNumber, int reason, Date revocationDate,
    X500Name issuerName) {
    super(CMCRequestType.revoke);
    this.serialNumber = serialNumber;
    this.reason = reason;
    this.revocationDate = revocationDate;
    this.issuerName = issuerName;
  }
  private X500Name issuerName;
  private BigInteger serialNumber;
  private int reason;
  private Date revocationDate;
}
