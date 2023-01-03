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

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.extension.AbstractExtensionModel;
import se.swedenconnect.cert.extensions.QCStatements;

/**
 * Extension data model
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class QCStatementsExtensionModel extends AbstractExtensionModel {

  /** Extension criticality */
  private final boolean critical;

  /** QC Statements */
  private final QCStatements qcStatements;

  /**
   * Constructor non critical extension
   *
   * @param qcStatements QC Statements
   */
  public QCStatementsExtensionModel(final QCStatements qcStatements) {
    this.qcStatements = qcStatements;
    this.critical = false;
  }

  /**
   * Constructor non critical extension
   *
   * @param qcStatements QC Statements
   * @param critical extension criticality
   */
  public QCStatementsExtensionModel(final QCStatements qcStatements, final boolean critical) {
    this.qcStatements = qcStatements;
    this.critical = critical;
  }

  /** {@inheritDoc} */
  @Override
  protected ExtensionMetadata getExtensionMetadata() {
    return new ExtensionMetadata(Extension.qCStatements, "Qualified certificate statements", this.critical);
  }

  /** {@inheritDoc} */
  @Override
  protected ASN1Object getExtensionObject() throws CertificateIssuanceException {
    if (this.qcStatements == null) {
      throw new CertificateIssuanceException("No QC Statements data");
    }
    return this.qcStatements;
  }
}
