/*
 * Copyright 2021-2023 Agency for Digital Government (DIGG)
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
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.extension.AbstractExtensionModel;

/**
 * Extension data model
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyUsageModel extends AbstractExtensionModel {

  /** Extension criticality */
  private final boolean critical;

  /** Authority key identifier extension data */
  private final KeyUsage keyUsage;

  /**
   * Constructor default critical
   *
   * @param keyUsage authority key identifier extension data
   */
  public KeyUsageModel(final int keyUsage) {
    this.keyUsage = new KeyUsage(keyUsage);
    this.critical = true;
  }

  /**
   * Constructor
   *
   * @param keyUsage authority key identifier extension data
   * @param critical extension criticality
   */
  public KeyUsageModel(final int keyUsage, final boolean critical) {
    this.keyUsage = new KeyUsage(keyUsage);
    this.critical = true;
  }

  /** {@inheritDoc} */
  @Override
  protected ExtensionMetadata getExtensionMetadata() {
    return new ExtensionMetadata(Extension.keyUsage, "Key usage", this.critical);
  }

  /** {@inheritDoc} */
  @Override
  protected ASN1Object getExtensionObject() throws CertificateIssuanceException {
    return this.keyUsage;
  }
}
