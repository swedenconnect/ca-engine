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
package se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.extension.AbstractExtensionModel;

/**
 * Extension data model.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class BasicConstraintsModel extends AbstractExtensionModel {

  /** Extension criticality */
  private final boolean critical;

  private final BasicConstraints basicConstraints;

  /**
   * Constructor
   *
   * @param ca true if the certificate is issued to a CA
   * @param critical extension criticality
   */
  public BasicConstraintsModel(final boolean ca, final boolean critical) {
    this.basicConstraints = new BasicConstraints(ca);
    this.critical = critical;
  }

  /**
   * Constructor
   *
   * @param pathLen path len constraint for CA
   * @param critical extension criticality
   */
  public BasicConstraintsModel(final int pathLen, final boolean critical) {
    this.basicConstraints = new BasicConstraints(pathLen);
    this.critical = critical;
  }

  /** {@inheritDoc} */
  @Override
  protected ExtensionMetadata getExtensionMetadata() {
    return new ExtensionMetadata(Extension.basicConstraints, "Basic constraints", this.critical);
  }

  /** {@inheritDoc} */
  @Override
  protected ASN1Object getExtensionObject() throws CertificateIssuanceException {
    return this.basicConstraints;
  }
}
