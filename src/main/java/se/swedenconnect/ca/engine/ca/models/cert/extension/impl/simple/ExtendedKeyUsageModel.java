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
package se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.extension.AbstractExtensionModel;

/**
 * Extension data model
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedKeyUsageModel extends AbstractExtensionModel {

  /** Extension criticality */
  private final boolean critical;

  private final ExtendedKeyUsage extendedKeyUsage;

  /**
   * Constructor
   *
   * @param critical extension criticality
   * @param keyPurposeIds one or more key purpose IDs
   */
  public ExtendedKeyUsageModel(final boolean critical, final KeyPurposeId... keyPurposeIds) {
    this.extendedKeyUsage = new ExtendedKeyUsage(keyPurposeIds);
    this.critical = critical;
  }

  /**
   * Constructor for critical extension
   *
   * @param keyPurposeIds one or more key purpose IDs
   */
  public ExtendedKeyUsageModel(final KeyPurposeId... keyPurposeIds) {
    this.extendedKeyUsage = new ExtendedKeyUsage(keyPurposeIds);
    this.critical = true;
  }

  /** {@inheritDoc} */
  @Override
  protected ExtensionMetadata getExtensionMetadata() {
    return new ExtensionMetadata(Extension.extendedKeyUsage, "Extended key usage", this.critical);
  }

  /** {@inheritDoc} */
  @Override
  protected ASN1Object getExtensionObject() throws CertificateIssuanceException {
    if (this.extendedKeyUsage.getUsages() == null || this.extendedKeyUsage.getUsages().length == 0) {
      throw new CertificateIssuanceException("At least one extended key usage id must be present");
    }
    return this.extendedKeyUsage;
  }
}
