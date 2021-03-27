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

package se.swedenconnect.ca.engine.revocation.crl.impl;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuer;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;

/**
 * Abstract CRL issuer
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractCRLIssuer implements CRLIssuer {

  /** Issuer private key */
  private final PrivateKey issuerPrivateKey;
  /** Issuer certificate */
  private final X509CertificateHolder issuerCertificate;
  /** Signature algorithm properties */
  private final CAAlgorithmRegistry.SignatureAlgorithmProperties algorithmProperties;

  /**
   * Constructor of the CRL issuer
   *
   * @param issuerPrivateKey  private issuing key
   * @param issuerCertificate CRL issuer certificate
   * @param algorithm         algorithm used to sign CRL
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   */
  public AbstractCRLIssuer(PrivateKey issuerPrivateKey, X509CertificateHolder issuerCertificate, String algorithm)
    throws NoSuchAlgorithmException {
    this.issuerPrivateKey = issuerPrivateKey;
    this.issuerCertificate = issuerCertificate;
    this.algorithmProperties = CAAlgorithmRegistry.getAlgorithmProperties(algorithm);
  }

  /**
   * Creates a complete Authority key identifier which includes the name of the issuer, the issuer certificate serial number and the issuer
   * SKI value
   *
   * @return Authority key identifier
   * @throws CertificateEncodingException problems parsing the issuer certificate
   * @throws IOException                  problems parsing the issuer certificate
   */
  protected AuthorityKeyIdentifier getAki() throws CertificateEncodingException, IOException {
    GeneralNames generalNames = new GeneralNames(new GeneralName[] {
      new GeneralName(GeneralName.directoryName, issuerCertificate.getSubject().toASN1Primitive())
    });
    Extension issuerSkiExt = issuerCertificate.getExtension(Extension.subjectKeyIdentifier);
    byte[] issuerSkiVal = issuerSkiExt == null
      ? null
      : SubjectKeyIdentifier.getInstance(issuerSkiExt.getParsedValue()).getKeyIdentifier();

    AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(issuerSkiVal, generalNames, issuerCertificate.getSerialNumber());
    return aki;
  }

  /**
   * Get a content signer
   *
   * @return content signer
   * @throws OperatorCreationException error creating the content signer
   */
  protected ContentSigner getContentSigner() throws OperatorCreationException {
    return (new JcaContentSignerBuilder(algorithmProperties.getSigAlgoName())).build(issuerPrivateKey);
  }

}
