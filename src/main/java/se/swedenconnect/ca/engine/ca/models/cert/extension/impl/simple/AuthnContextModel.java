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

import java.util.List;

import org.bouncycastle.asn1.ASN1Object;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.extension.AbstractExtensionModel;
import se.swedenconnect.cert.extensions.AuthnContext;
import se.swedenconnect.cert.extensions.AuthnContextEntry;
import se.swedenconnect.cert.extensions.data.ProtocolAuthContext;

/**
 * Extension data model.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AuthnContextModel extends AbstractExtensionModel {

  /** Extension criticality */
  private final boolean critical;

  /** Authentication context data (SAML or OpenID Connect) */
  private final ProtocolAuthContext authContext;

  /**
   * Constructor
   *
   * @param authContext authentication context data, SAML Authentication Context Information or OpenID Connect
   *          Authentication Context Information
   * @param critical extension criticality
   */
  public AuthnContextModel(final ProtocolAuthContext authContext, final boolean critical) {
    this.authContext = authContext;
    this.critical = critical;
  }

  /**
   * Constructor for non critical extension
   *
   * @param authContext authentication context data, SAML Authentication Context Information or OpenID Connect
   *          Authentication Context Information
   */
  public AuthnContextModel(final ProtocolAuthContext authContext) {
    this(authContext, false);
  }

  /** {@inheritDoc} */
  @Override
  protected ExtensionMetadata getExtensionMetadata() {
    return new ExtensionMetadata(AuthnContext.OID, "Authentication context", this.critical);
  }

  /** {@inheritDoc} */
  @Override
  protected ASN1Object getExtensionObject() throws CertificateIssuanceException {
    return AuthnContext.fromEntries(List.of(new AuthnContextEntry(this.authContext)));
  }
}
