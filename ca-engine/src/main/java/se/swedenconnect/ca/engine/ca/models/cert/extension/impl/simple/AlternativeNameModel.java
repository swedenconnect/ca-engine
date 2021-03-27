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

package se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple;

import lombok.Setter;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.extension.AbstractExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.EntityType;

/**
 * Extension data model
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AlternativeNameModel extends AbstractExtensionModel {

  /** Extension criticality */
  @Setter boolean critical = false;

  /** indicates if this is an issuer or subject alternative name */
  private final EntityType entityType;

  /** General names */
  GeneralName[] generalNames;

  /**
   * Constructor with criticality default false
   *
   * @param entityType   indicates if this is an issuer or subject alternative name
   * @param generalNames alternative names
   */
  public AlternativeNameModel(EntityType entityType, GeneralName... generalNames) {
    this.entityType = entityType;
    this.generalNames = generalNames;
  }

  /** {@inheritDoc} */
  @Override protected ExtensionMetadata getExtensionMetadata() {
    return entityType.equals(EntityType.subject)
      ? new ExtensionMetadata(Extension.subjectAlternativeName, "Subject alternative name", critical)
      : new ExtensionMetadata(Extension.issuerAlternativeName, "Issuer alternative name", critical);
  }

  /** {@inheritDoc} */
  @Override protected ASN1Object getExtensionObject() throws CertificateIssuanceException {
    if (generalNames == null || generalNames.length == 0) {
      throw new CertificateIssuanceException("Alternative name extension must not be empty");
    }
    return new GeneralNames(generalNames);
  }
}
