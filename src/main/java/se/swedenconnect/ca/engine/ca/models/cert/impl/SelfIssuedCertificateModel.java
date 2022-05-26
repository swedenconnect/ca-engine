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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;

/**
 * Model class for a self-issued certificate.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
public class SelfIssuedCertificateModel extends CertificateModel {

  /**
   * Private key
   *
   * @param privateKey private key
   * @return private key
   */
  private PrivateKey privateKey;

  /**
   * Constructor
   *
   * @param privateKey private key
   */
  public SelfIssuedCertificateModel(final PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  /**
   * Create certificate model for self issued certificate
   *
   * @param model certificate model
   * @param privateKey private key
   */
  public SelfIssuedCertificateModel(final CertificateModel model, final PrivateKey privateKey) {
    super(model.getSubject(), model.getPublicKey(), model.getExtensionModels());
    this.privateKey = privateKey;
  }

  /**
   * Create certificate model for self issued certificate
   *
   * @param subject subject
   * @param publicKey public key
   * @param extensionModels extension models
   * @param privateKey private key
   */
  public SelfIssuedCertificateModel(final CertNameModel<?> subject, final PublicKey publicKey,
      final List<ExtensionModel> extensionModels, final PrivateKey privateKey) {
    super(subject, publicKey, extensionModels);
    this.privateKey = privateKey;
  }
}
