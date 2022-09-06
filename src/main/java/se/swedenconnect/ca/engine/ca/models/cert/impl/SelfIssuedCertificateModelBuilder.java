/*
 * Copyright (c) 2021-2022. Agency for Digital Government (DIGG)
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

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.AuthorityKeyIdentifierModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.SubjectKeyIdentifierModel;

/**
 * Model builder for self issued certificates.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SelfIssuedCertificateModelBuilder
    extends AbstractCertificateModelBuilder<SelfIssuedCertificateModelBuilder> {

  private final PrivateKey privateKey;

  private final PublicKey publicKey;

  private final CertificateIssuerModel certificateIssuerModel;

  /**
   * Private constructor
   *
   * @param privateKey private issuing key
   * @param publicKey public key of the certificate subject
   * @param certificateIssuerModel certificate issuer configuration data
   */
  private SelfIssuedCertificateModelBuilder(final PrivateKey privateKey, final PublicKey publicKey,
      final CertificateIssuerModel certificateIssuerModel) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.certificateIssuerModel = certificateIssuerModel;
  }

  /**
   * Creates an instance of this certificate model builder
   *
   * @param privateKey private issuing key
   * @param publicKey public key of the certificate subject
   * @param certificateIssuerModel certificate issuer configuration data
   * @return certificate model builder
   */
  public static SelfIssuedCertificateModelBuilder getInstance(final PrivateKey privateKey, final PublicKey publicKey,
      final CertificateIssuerModel certificateIssuerModel) {
    return new SelfIssuedCertificateModelBuilder(privateKey, publicKey, certificateIssuerModel);
  }

  /**
   * Creates an instance of this certificate model builder
   *
   * @param keyPair key pair of the certificate issuer and subject
   * @param certificateIssuerModel certificate issuer configuration data
   * @return certificate model builder
   */
  public static SelfIssuedCertificateModelBuilder getInstance(final KeyPair keyPair,
      final CertificateIssuerModel certificateIssuerModel) {
    return new SelfIssuedCertificateModelBuilder(keyPair.getPrivate(), keyPair.getPublic(), certificateIssuerModel);
  }

  /** {@inheritDoc} */
  @Override
  public CertificateModel build() throws CertificateIssuanceException {
    return new SelfIssuedCertificateModel(super.build(), this.privateKey);
  }

  /** {@inheritDoc} */
  @Override
  protected PublicKey getPublicKey() {
    return this.publicKey;
  }

  /** {@inheritDoc} */
  @Override
  protected void addKeyIdentifierExtensionsModels(final List<ExtensionModel> extensionModelList) throws IOException {

    // Authority key identifier
    if (this.includeAki) {
      extensionModelList.add(new AuthorityKeyIdentifierModel(new AuthorityKeyIdentifier(
          this.certificateIssuerModel.getSigAlgoMessageDigest().digest(this.publicKey.getEncoded()))));
    }

    // Subject key identifier
    if (this.includeSki) {
      extensionModelList.add(new SubjectKeyIdentifierModel(
          this.certificateIssuerModel.getSigAlgoMessageDigest().digest(this.publicKey.getEncoded())));
    }

  }
}
