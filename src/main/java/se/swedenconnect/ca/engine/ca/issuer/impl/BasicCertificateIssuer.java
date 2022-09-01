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

package se.swedenconnect.ca.engine.ca.issuer.impl;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.security.credential.PkiCredential;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.util.List;

/**
 * Basic certificate issuer implementation
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class BasicCertificateIssuer extends CertificateIssuer {

  /** name of the certificate issuer */
  private final X500Name issuerName;
  /** private key of the certificate issuer */
  private final PkiCredential issuerCredential;

  /**
   * Constructor for this certificate issuer implementation
   *
   * @param certificateIssuerModel certificate issuer configuration data
   * @param issuerCredential       private key and issuing certificates of the certificate issuer
   */
  public BasicCertificateIssuer(final CertificateIssuerModel certificateIssuerModel, final PkiCredential issuerCredential){
    super(certificateIssuerModel);
    this.issuerCredential = issuerCredential;
    try {
      this.issuerName = new JcaX509CertificateHolder(issuerCredential.getCertificate()).getSubject();
    }
    catch (CertificateEncodingException e) {
      // Throwing an unchecked runtime exception. There is no legal way that a valid PkiCredential will not contain a valid
      // certificate with a valid issuer name. Any such situation is non-recoverable
      log.error("PkiCredential does not contain a valid issuer certificate");
      throw new RuntimeException(e);
    }
  }

  /** {@inheritDoc} */
  @Override public X509CertificateHolder issueCertificate(CertificateModel model) throws CertificateIssuanceException {

    try {
      return certificateIssuerModel.isV1() && model.getExtensionModels().isEmpty()
        ? issueV1Certificate(model)
        : issueV3Certificate(model);
    }
    catch (OperatorCreationException e) {
      log.error("Error creating signer", e);
      throw new CertificateIssuanceException("Error creating the signer", e);
    }
    catch (IOException e) {
      log.info("Illegal subject name in certificate request");
      throw new CertificateIssuanceException("Illegal subject name");
    }
  }

  /**
   * Build a version 3 certificate
   *
   * @param model model defining the content of the certificate to issue
   * @return issued certificate
   * @throws IOException               error parsing name
   * @throws OperatorCreationException error creating content signer
   */
  private X509CertificateHolder issueV3Certificate(CertificateModel model) throws IOException, OperatorCreationException {
    JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
      issuerName,
      certificateIssuerModel.getSerialNumberProvider().getSerialNumber(),
      CertificateIssuer.getOffsetTime(certificateIssuerModel.getStartOffset()),
      CertificateIssuer.getOffsetTime(certificateIssuerModel.getExpiryOffset()),
      getX500Name(model.getSubject()),
      model.getPublicKey()
    );

    List<ExtensionModel> extensionModels = model.getExtensionModels();
    for (ExtensionModel extensionModel : extensionModels) {
      extensionModel.addExtensions(certificateBuilder);
    }
    return certificateBuilder.build((new JcaContentSignerBuilder(certificateIssuerModel.getAlgorithmName())).build(issuerCredential.getPrivateKey()));
  }

  /**
   * Build a version 1 certificate
   *
   * @param model model defining the content of the certificate to issue
   * @return issued certificate
   * @throws IOException               error parsing name
   * @throws OperatorCreationException error creating content signer
   */
  private X509CertificateHolder issueV1Certificate(CertificateModel model) throws OperatorCreationException, IOException {
    JcaX509v1CertificateBuilder certificateBuilder = new JcaX509v1CertificateBuilder(
      issuerName,
      certificateIssuerModel.getSerialNumberProvider().getSerialNumber(),
      CertificateIssuer.getOffsetTime(certificateIssuerModel.getStartOffset()),
      CertificateIssuer.getOffsetTime(certificateIssuerModel.getExpiryOffset()),
      getX500Name(model.getSubject()),
      model.getPublicKey()
    );
    return certificateBuilder.build((new JcaContentSignerBuilder(certificateIssuerModel.getAlgorithmName())).build(issuerCredential.getPrivateKey()));
  }

}
