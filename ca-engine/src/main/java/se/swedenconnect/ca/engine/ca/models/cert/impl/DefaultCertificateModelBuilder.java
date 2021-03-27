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

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.AuthorityKeyIdentifierModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.SubjectKeyIdentifierModel;

import java.io.IOException;
import java.security.PublicKey;
import java.util.List;

/**
 * Default certificate model builder implementation
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
   * @param publicKey              subject public key
   * @param issuer                 issuer certificate
   * @param certificateIssuerModel certificate issuer configuration data
   */
  private DefaultCertificateModelBuilder(PublicKey publicKey, X509CertificateHolder issuer,
    CertificateIssuerModel certificateIssuerModel) {
    this.publicKey = publicKey;
    this.issuer = issuer;
    this.certificateIssuerModel = certificateIssuerModel;
  }

  /**
   * Creates an instance of this certificate model builder
   *
   * @param publicKey              subject public key
   * @param issuer                 issuer certificate
   * @param certificateIssuerModel certificate issuer configuration data
   * @return certificate model builder
   */
  public static DefaultCertificateModelBuilder getInstance(PublicKey publicKey, X509CertificateHolder issuer,
    CertificateIssuerModel certificateIssuerModel) {
    return new DefaultCertificateModelBuilder(publicKey, issuer, certificateIssuerModel);
  }

  @Override public CertificateModel build() throws CertificateIssuanceException {
    try {
      return CertificateModel.builder()
        .publicKey(publicKey)
        .subject(getSubject())
        .extensionModels(getExtensionModels())
        .build();
    }
    catch (Exception ex) {
      throw new CertificateIssuanceException("Failed to prepare certificate data", ex);
    }
  }

  @Override
  protected void getKeyIdentifierExtensionsModels(List<ExtensionModel> extm) throws IOException {

    //Authority key identifier
    if (includeAki) {
      AuthorityKeyIdentifierModel akiModel = null;
      try {
        byte[] kidVal = SubjectKeyIdentifier.getInstance(issuer.getExtension(Extension.subjectKeyIdentifier).getParsedValue())
          .getKeyIdentifier();
        if (kidVal != null && kidVal.length > 0) {
          akiModel = new AuthorityKeyIdentifierModel(new AuthorityKeyIdentifier(kidVal));
        }
      }
      catch (Exception ignored) {
      }

      if (akiModel == null) {
        akiModel = new AuthorityKeyIdentifierModel(new AuthorityKeyIdentifier(
          certificateIssuerModel.getSigAlgoMessageDigest().digest(issuer.getSubjectPublicKeyInfo().getEncoded())
        ));
      }
      extm.add(akiModel);
    }

    // Subject key identifier
    if (includeSki) {
      extm.add(new SubjectKeyIdentifierModel(
        certificateIssuerModel.getSigAlgoMessageDigest().digest(publicKey.getEncoded())
      ));
    }

  }
}
