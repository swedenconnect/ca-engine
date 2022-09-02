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

import java.io.IOException;
import java.security.PublicKey;
import java.util.List;

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.AuthorityKeyIdentifierModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.SubjectKeyIdentifierModel;

/**
 * Default certificate model builder implementation.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultCertificateModelBuilder extends AbstractCertificateModelBuilder<DefaultCertificateModelBuilder> {

  /** Subject public key */
  private final PublicKey publicKey;

  /** Certificate of the issuer */
  private final X509CertificateHolder issuer;

  /** Configuration data of the certificate issuer */
  private final CertificateIssuerModel certificateIssuerModel;

  /**
   * Private constructor
   *
   * @param publicKey subject public key
   * @param issuer issuer certificate
   * @param certificateIssuerModel certificate issuer configuration data
   */
  private DefaultCertificateModelBuilder(final PublicKey publicKey, final X509CertificateHolder issuer,
      final CertificateIssuerModel certificateIssuerModel) {
    this.publicKey = publicKey;
    this.issuer = issuer;
    this.certificateIssuerModel = certificateIssuerModel;
  }

  /**
   * Creates an instance of this certificate model builder
   *
   * @param publicKey subject public key
   * @param issuer issuer certificate
   * @param certificateIssuerModel certificate issuer configuration data
   * @return certificate model builder
   */
  public static DefaultCertificateModelBuilder getInstance(final PublicKey publicKey,
      final X509CertificateHolder issuer,
      final CertificateIssuerModel certificateIssuerModel) {
    return new DefaultCertificateModelBuilder(publicKey, issuer, certificateIssuerModel);
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
      AuthorityKeyIdentifierModel akiModel = null;
      try {
        final byte[] kidVal =
            SubjectKeyIdentifier.getInstance(this.issuer.getExtension(Extension.subjectKeyIdentifier).getParsedValue())
                .getKeyIdentifier();
        if (kidVal != null && kidVal.length > 0) {
          akiModel = new AuthorityKeyIdentifierModel(new AuthorityKeyIdentifier(kidVal));
        }
      }
      catch (final Exception ignored) {
      }

      if (akiModel == null) {
        akiModel = new AuthorityKeyIdentifierModel(new AuthorityKeyIdentifier(
            this.certificateIssuerModel.getSigAlgoMessageDigest()
                .digest(this.issuer.getSubjectPublicKeyInfo().getEncoded())));
      }
      extensionModelList.add(akiModel);
    }

    // Subject key identifier
    if (this.includeSki) {
      extensionModelList.add(new SubjectKeyIdentifierModel(
          this.certificateIssuerModel.getSigAlgoMessageDigest().digest(this.publicKey.getEncoded())));
    }

  }
}
