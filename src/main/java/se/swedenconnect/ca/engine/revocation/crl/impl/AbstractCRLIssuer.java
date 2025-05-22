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
package se.swedenconnect.ca.engine.revocation.crl.impl;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuer;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Abstract CRL issuer.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractCRLIssuer implements CRLIssuer {

  /** Issuer private key */
  private final PkiCredential issuerCredential;

  /** Issuer certificate */
  private final X509CertificateHolder issuerCertificate;

  /** Signature algorithm properties */
  private final CAAlgorithmRegistry.SignatureAlgorithmProperties algorithmProperties;

  /** Provider of CRL revocation data */
  protected final CRLRevocationDataProvider crlRevocationDataProvider;


  /**
   * Constructor of the CRL issuer.
   *
   * @param issuerCredential credentials of the certificate issuer
   * @param crlRevocationDataProvider provider of CRL revocation data regarding the state of revoked certificates
   * @param algorithm algorithm used to sign CRL
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   */
  public AbstractCRLIssuer(final PkiCredential issuerCredential, final String algorithm,
    final CRLRevocationDataProvider crlRevocationDataProvider)
      throws NoSuchAlgorithmException {
    this.issuerCredential = issuerCredential;
    this.crlRevocationDataProvider = crlRevocationDataProvider;
    this.algorithmProperties = CAAlgorithmRegistry.getAlgorithmProperties(algorithm);
    try {
      this.issuerCertificate = new JcaX509CertificateHolder(issuerCredential.getCertificate());
    }
    catch (final CertificateEncodingException e) {
      log.error("The PKI credentials for the CRL issuer does not contain a valid signing certificate");
      throw new RuntimeException(e);
    }
  }

  /**
   * Creates a complete Authority key identifier which includes the name of the issuer, the issuer certificate serial
   * number and the issuer SKI value.
   *
   * @return Authority key identifier
   * @throws CertificateEncodingException problems parsing the issuer certificate
   * @throws IOException problems parsing the issuer certificate
   */
  protected AuthorityKeyIdentifier getAki() throws CertificateEncodingException, IOException {
    final GeneralNames generalNames = new GeneralNames(new GeneralName[] {
        new GeneralName(GeneralName.directoryName, this.issuerCertificate.getSubject().toASN1Primitive())
    });
    final Extension issuerSkiExt = this.issuerCertificate.getExtension(Extension.subjectKeyIdentifier);
    final byte[] issuerSkiVal = issuerSkiExt == null
        ? null
        : SubjectKeyIdentifier.getInstance(issuerSkiExt.getParsedValue()).getKeyIdentifier();

    final AuthorityKeyIdentifier aki =
        new AuthorityKeyIdentifier(issuerSkiVal, generalNames, this.issuerCertificate.getSerialNumber());
    return aki;
  }

  /**
   * Get a content signer.
   *
   * @return content signer
   * @throws OperatorCreationException error creating the content signer
   */
  protected ContentSigner getContentSigner() throws OperatorCreationException {
    return new JcaContentSignerBuilder(this.algorithmProperties.getSigAlgoName())
        .build(this.issuerCredential.getPrivateKey());
  }

}
