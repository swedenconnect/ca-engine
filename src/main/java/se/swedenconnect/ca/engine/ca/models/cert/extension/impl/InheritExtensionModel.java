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
package se.swedenconnect.ca.engine.ca.models.cert.extension.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionIdAndCrit;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;

/**
 * This certificate extension model copies extension data from an existing certificate.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class InheritExtensionModel implements ExtensionModel {

  /** Certificate to inherit extensions from. */
  private final X509CertificateHolder certificateHolder;

  /** List of extensions to copy from certficate. */
  private final List<ExtensionIdAndCrit> extensionIdList;

  /**
   * Constructor.
   *
   * @param certificateHolder master certificate holding extensions to copy
   * @param extensionId list of extensions to copy
   */
  public InheritExtensionModel(final X509CertificateHolder certificateHolder, final ExtensionIdAndCrit... extensionId) {
    this.certificateHolder = certificateHolder;
    this.extensionIdList = Arrays.asList(extensionId);
  }

  /** {@inheritDoc} */
  @Override
  public void addExtensions(final JcaX509v3CertificateBuilder certificateBuilder) throws CertificateIssuanceException {
    try {
      for (final ExtensionIdAndCrit extensionIdAndCrit : this.extensionIdList) {
        certificateBuilder.copyAndAddExtension(extensionIdAndCrit.getOid(), extensionIdAndCrit.isCritical(),
            this.certificateHolder);
        log.debug("Added extension copy from cert {}", extensionIdAndCrit.getOid());
      }
    }
    catch (final Exception ex) {
      throw new CertificateIssuanceException("Error while attempting to copy extension from cert", ex);
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<Extension> getExtensions() throws CertificateIssuanceException {
    try {
      final List<Extension> extensionList = new ArrayList<>();
      for (final ExtensionIdAndCrit extensionIdAndCrit : this.extensionIdList) {
        final Extension extractExtension = this.certificateHolder.getExtension(extensionIdAndCrit.getOid());
        final Extension newExtension = new Extension(extensionIdAndCrit.getOid(), extensionIdAndCrit.isCritical(),
            extractExtension.getExtnValue());
        extensionList.add(newExtension);
        log.debug("Added extension copy from cert {}", extensionIdAndCrit.getOid());
      }
      return extensionList;
    }
    catch (final Exception ex) {
      throw new CertificateIssuanceException("Error while attempting to copy extension from cert", ex);
    }
  }
}
