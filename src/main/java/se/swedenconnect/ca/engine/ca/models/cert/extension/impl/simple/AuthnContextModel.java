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

import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Object;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.extension.AbstractExtensionModel;
import se.swedenconnect.cert.extensions.AuthnContext;
import se.swedenconnect.cert.extensions.data.saci.SAMLAuthContext;

/**
 * Extension data model.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AuthnContextModel extends AbstractExtensionModel {

  /** Extension criticality */
  private final boolean critical;

  /** Authn context data */
  private final SAMLAuthContext samlAuthContext;

  /**
   * Constructor for non critical extension
   *
   * @param samlAuthnContext SAMLAuthContext data
   * @param critical extension criticality
   */
  public AuthnContextModel(final SAMLAuthContext samlAuthnContext, final boolean critical) {
    this.samlAuthContext = samlAuthnContext;
    this.critical = critical;
  }

  /**
   * Constructor for non critical extension
   *
   * @param samlAuthnContext SAMLAuthContext data
   */
  public AuthnContextModel(final SAMLAuthContext samlAuthnContext) {
    this.samlAuthContext = samlAuthnContext;
    this.critical = false;
  }

  /** {@inheritDoc} */
  @Override
  protected ExtensionMetadata getExtensionMetadata() {
    return new ExtensionMetadata(AuthnContext.OID, "Authentication context", this.critical);
  }

  /** {@inheritDoc} */
  @Override
  protected ASN1Object getExtensionObject() throws CertificateIssuanceException {
    return new AuthnContext(Arrays.asList(this.samlAuthContext));
  }
}
