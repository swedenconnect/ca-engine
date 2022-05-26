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

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.extension.AbstractExtensionModel;

/**
 * Generic certificate extension model that can be used to build any extension based on ASN.1 data structure.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class GenericExtensionModel extends AbstractExtensionModel {

  /** Extension OID */
  private final ASN1ObjectIdentifier oid;

  /** Extension data */
  private final ASN1Object extensionObject;

  /** Extension criticality */
  private final boolean critical;

  /**
   * Create extension model
   *
   * @param oid extension OID
   * @param extensionObject extension data
   */
  public GenericExtensionModel(final ASN1ObjectIdentifier oid, final ASN1Object extensionObject) {
    this.oid = oid;
    this.extensionObject = extensionObject;
    this.critical = false;
  }

  /**
   * Create extension model
   *
   * @param oid extension OID
   * @param extensionObject extension data
   * @param critical extension criticality
   */
  public GenericExtensionModel(final ASN1ObjectIdentifier oid, final ASN1Object extensionObject,
      final boolean critical) {
    this.oid = oid;
    this.extensionObject = extensionObject;
    this.critical = critical;
  }

  /**
   * Get extension metadata
   *
   * @return {@link ExtensionMetadata}
   */
  @Override
  protected ExtensionMetadata getExtensionMetadata() {
    return new ExtensionMetadata(this.oid, "certificate", this.critical);
  }

  /**
   * Get extension data
   *
   * @return {@link ASN1Object} data
   * @throws CertificateIssuanceException error parsing data
   */
  @Override
  protected ASN1Object getExtensionObject() throws CertificateIssuanceException {
    return this.extensionObject;
  }
}
