/*
 * Copyright 2024 Agency for Digital Government (DIGG)
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
package se.swedenconnect.ca.engine.ca.models.cert.extension;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;

/**
 * Abstract model for extension data.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractExtensionModel implements ExtensionModel {

  /**
   * Gets the extension metadata
   *
   * @return extension metadata
   */
  protected abstract ExtensionMetadata getExtensionMetadata();

  /**
   * Gets extension data object
   *
   * @return extension data object
   * @throws CertificateIssuanceException if extension data is not legal
   */
  protected abstract ASN1Object getExtensionObject() throws CertificateIssuanceException;

  /** {@inheritDoc} */
  @Override
  public void addExtensions(final JcaX509v3CertificateBuilder certificateBuilder) throws CertificateIssuanceException {
    try {
      certificateBuilder.addExtension(this.getExtensions().get(0));
      log.debug("Added extension");
    }
    catch (final IOException e) {
      throw new CertificateIssuanceException("Unable to encode extension", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<Extension> getExtensions() throws CertificateIssuanceException {
    final ASN1Object extensionObject = this.getExtensionObject();
    final ExtensionMetadata emd = this.getExtensionMetadata();
    try {
      final Extension extension = new Extension(emd.getOid(), emd.isCritical(), extensionObject.getEncoded("DER"));
      log.debug("Encoded " + emd.getName() + " extension");
      return Arrays.asList(extension);
    }
    catch (final IOException e) {
      throw new CertificateIssuanceException("Unable to encode " + emd.getName() + " extension", e);
    }
  }

  /**
   * Metadata for a certificate extension.
   */
  @Getter
  @AllArgsConstructor
  protected class ExtensionMetadata {

    /**
     * Extension object identifier.
     *
     * @return extension object identifier
     */
    private final ASN1ObjectIdentifier oid;

    /**
     * Extension name.
     *
     * @return extension name
     */
    private final String name;

    /**
     * Extension criticality.
     *
     * @return extension criticality
     */
    private final boolean critical;
  }

}
