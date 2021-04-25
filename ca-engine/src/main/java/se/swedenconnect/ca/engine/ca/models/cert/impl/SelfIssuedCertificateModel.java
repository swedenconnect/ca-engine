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

package se.swedenconnect.ca.engine.ca.models.cert.impl;

import lombok.Data;
import lombok.NoArgsConstructor;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

/**
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@NoArgsConstructor
public class SelfIssuedCertificateModel extends CertificateModel {

  private PrivateKey privateKey;

  public SelfIssuedCertificateModel(PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  public SelfIssuedCertificateModel(CertificateModel model, PrivateKey privateKey) {
    super(model.getSubject(), model.getPublicKey(), model.getExtensionModels());
    this.privateKey = privateKey;
  }

  public SelfIssuedCertificateModel(CertNameModel subject, PublicKey publicKey,
    List<ExtensionModel> extensionModels, PrivateKey privateKey) {
    super(subject, publicKey, extensionModels);
    this.privateKey = privateKey;
  }
}