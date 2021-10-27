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

import lombok.*;
import org.bouncycastle.operator.ContentSigner;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Model for creating a CMC Certificate request
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public class CMCCertificateRequestModel extends AbstractCMCRequestModel {

  public CMCCertificateRequestModel(CertificateModel certificateModel, String profile) {
    super(CMCRequestType.issueCert, profile != null ? profile.getBytes(StandardCharsets.UTF_8) : null);
    this.certificateModel = certificateModel;
    this.lraPopWitness = true;
  }

  public CMCCertificateRequestModel(CertificateModel certificateModel, String profile,
    PrivateKey certReqPrivate, String p10Algorithm) {
    super(CMCRequestType.issueCert,profile != null ? profile.getBytes(StandardCharsets.UTF_8) : null);
    this.certificateModel = certificateModel;
    this.certReqPrivate = certReqPrivate;
    this.p10Algorithm = p10Algorithm;
    this.lraPopWitness = false;
  }

  /** Certificate request model */
  private CertificateModel certificateModel;
  /** Private key of the requested certificate used to sign PKCS#10 requests */
  private PrivateKey certReqPrivate;
  /** Algorithm URI identifier for the algorithm used to sign the pkcs10 request */
  private String p10Algorithm;
  /** Boolean to indicate if the requester has verified proof-of-possession of certified private key */
  private boolean lraPopWitness;
}
