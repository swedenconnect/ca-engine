/*
 * Copyright 2021-2025 Sweden Connect
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
package se.swedenconnect.ca.engine.ca.issuer.impl;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.SelfIssuedCertificateModel;

/**
 * A certificate issuer implementation for issuing self issued certificates.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class SelfIssuedCertificateIssuer extends CertificateIssuer {

  /**
   * Constructor.
   *
   * @param certificateIssuerModel configuration data for issuing self issued certificates
   */
  public SelfIssuedCertificateIssuer(final CertificateIssuerModel certificateIssuerModel) {
    super(certificateIssuerModel);
  }

  /** {@inheritDoc} */
  @Override
  public X509CertificateHolder issueCertificate(final CertificateModel model) throws CertificateIssuanceException {
    if (!(model instanceof SelfIssuedCertificateModel)) {
      throw new CertificateIssuanceException("Certificate model must be the SelfIssuedCertificateModel");
    }
    try {
      return this.certificateIssuerModel.isV1() && model.getExtensionModels().isEmpty()
          ? this.issueV1Certificate((SelfIssuedCertificateModel) model)
          : this.issueV3Certificate((SelfIssuedCertificateModel) model);
    }
    catch (final OperatorCreationException e) {
      log.error("Error creating signer", e);
      throw new CertificateIssuanceException("Error creating the signer", e);
    }
    catch (final IOException e) {
      log.info("Illegal subject name in certificate request");
      throw new CertificateIssuanceException("Illegal subject name");
    }
  }

  /**
   * Issue a Version 3 self issued certificate
   *
   * @param model configuration data for issuing self issued certificates
   * @return self issued certificate
   * @throws IOException error parsing name
   * @throws OperatorCreationException error creating content signer
   */
  private X509CertificateHolder issueV3Certificate(final SelfIssuedCertificateModel model)
      throws IOException, OperatorCreationException {
    final JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
        this.getX500Name(model.getSubject()),
        this.certificateIssuerModel.getSerialNumberProvider().getSerialNumber(),
        CertificateIssuer.getOffsetTime(this.certificateIssuerModel.getStartOffset()),
        CertificateIssuer.getOffsetTime(this.certificateIssuerModel.getExpiryOffset()),
        this.getX500Name(model.getSubject()),
        model.getPublicKey());

    final List<ExtensionModel> extensionModels = model.getExtensionModels();
    for (final ExtensionModel extensionModel : extensionModels) {
      extensionModel.addExtensions(certificateBuilder);
    }
    return certificateBuilder.build(
        new JcaContentSignerBuilder(this.certificateIssuerModel.getAlgorithmName()).build(model.getPrivateKey()));
  }

  /**
   * Issue a Version 3 self issued certificate
   *
   * @param model configuration data for issuing self issued certificates
   * @return self issued certificate
   * @throws IOException error parsing name
   * @throws OperatorCreationException error creating content signer
   */
  private X509CertificateHolder issueV1Certificate(final SelfIssuedCertificateModel model)
      throws IOException, OperatorCreationException {
    final JcaX509v1CertificateBuilder certificateBuilder = new JcaX509v1CertificateBuilder(
        this.getX500Name(model.getSubject()),
        this.certificateIssuerModel.getSerialNumberProvider().getSerialNumber(),
        CertificateIssuer.getOffsetTime(this.certificateIssuerModel.getStartOffset()),
        CertificateIssuer.getOffsetTime(this.certificateIssuerModel.getExpiryOffset()),
        this.getX500Name(model.getSubject()),
        model.getPublicKey());
    return certificateBuilder.build(
        new JcaContentSignerBuilder(this.certificateIssuerModel.getAlgorithmName()).build(model.getPrivateKey()));
  }

}
