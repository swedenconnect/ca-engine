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

package se.swedenconnect.ca.engine.ca.models.cert.extension.impl;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.extension.AbstractExtensionModel;

/**
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
@AllArgsConstructor
public class GenericExtensionModel extends AbstractExtensionModel {

  private ASN1ObjectIdentifier oid;
  private ASN1Object extensionObject;
  private boolean critical;

  public GenericExtensionModel(ASN1ObjectIdentifier oid, ASN1Object extensionObject) {
    this.oid = oid;
    this.extensionObject = extensionObject;
  }

  @Override protected ExtensionMetadata getExtensionMetadata() {
    return new ExtensionMetadata(oid, "certificate", critical);
  }

  @Override protected ASN1Object getExtensionObject() throws CertificateIssuanceException {
    return extensionObject;
  }
}
