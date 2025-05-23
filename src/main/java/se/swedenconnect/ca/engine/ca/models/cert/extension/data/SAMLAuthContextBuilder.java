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
package se.swedenconnect.ca.engine.ca.models.cert.extension.data;

import java.util.Date;
import java.util.List;

import org.w3c.dom.Element;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.cert.extensions.data.saci.AttributeMapping;
import se.swedenconnect.cert.extensions.data.saci.AuthContextInfo;
import se.swedenconnect.cert.extensions.data.saci.IdAttributes;
import se.swedenconnect.cert.extensions.data.saci.SAMLAuthContext;

/**
 * Builder for Authn Context data in the Authn Context extension.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SAMLAuthContextBuilder {

  /**
   * Private constructor
   */
  private SAMLAuthContextBuilder() {
  }

  /**
   * Creates an instance of this {@link SAMLAuthContextBuilder}
   *
   * @return {@link SAMLAuthContextBuilder}
   */
  public static SAMLAuthContextBuilder instance() {
    return new SAMLAuthContextBuilder();
  }

  /** Assertion reference */
  private String assertionRef;

  /** LoA identifier */
  private String authnContextClassRef;

  /** Authentication time when user/subject was authenticated */
  private Date authenticationInstant;

  /** Identity provider performing Authentication */
  private String identityProvider;

  /** Service identifier */
  private String serviceID;

  /** Extension data */
  private List<Element> extensions;

  /** Attribute mappings */
  private List<AttributeMapping> attributeMappings;

  /**
   * Set assertion reference
   *
   * @param assertionRef assertion reference/identifier
   * @return this builder
   */
  public SAMLAuthContextBuilder assertionRef(final String assertionRef) {
    this.assertionRef = assertionRef;
    return this;
  }

  /**
   * Set level of assurance
   *
   * @param authnContextClassRef level of assurance
   * @return this builder
   */
  public SAMLAuthContextBuilder authnContextClassRef(final String authnContextClassRef) {
    this.authnContextClassRef = authnContextClassRef;
    return this;
  }

  /**
   * Set time of authentication
   *
   * @param authenticationInstant time of authentication
   * @return this builder
   */
  public SAMLAuthContextBuilder authenticationInstant(final Date authenticationInstant) {
    this.authenticationInstant = authenticationInstant;
    return this;
  }

  /**
   * Set identity provider
   *
   * @param identityProvider identity provider
   * @return this builder
   */
  public SAMLAuthContextBuilder identityProvider(final String identityProvider) {
    this.identityProvider = identityProvider;
    return this;
  }

  /**
   * Set service identifier
   *
   * @param serviceID service identifier
   * @return this builder
   */
  public SAMLAuthContextBuilder serviceID(final String serviceID) {
    this.serviceID = serviceID;
    return this;
  }

  /**
   * Set extension
   *
   * @param extensions extensions
   * @return this builder
   */
  public SAMLAuthContextBuilder extensions(final List<Element> extensions) {
    this.extensions = extensions;
    return this;
  }

  /**
   * Set attribute mappings
   *
   * @param attributeMappings attribute mappings
   * @return this builder
   */
  public SAMLAuthContextBuilder attributeMappings(final List<AttributeMapping> attributeMappings) {
    this.attributeMappings = attributeMappings;
    return this;
  }

  /**
   * Build SAML Authentication context
   *
   * @return {@link SAMLAuthContext}
   * @throws CertificateIssuanceException error building the SAMLAuthContext object
   */
  public SAMLAuthContext build() throws CertificateIssuanceException {

    final SAMLAuthContext samlAuthContext = new SAMLAuthContext(false);
    final AuthContextInfo aci = new AuthContextInfo();
    samlAuthContext.setAuthContextInfo(aci);
    aci.setAssertionRef(this.assertionRef);
    aci.setAuthenticationInstant(this.authenticationInstant.toInstant());
    aci.setAuthnContextClassRef(this.authnContextClassRef);
    aci.setIdentityProvider(this.identityProvider);
    aci.setServiceID(this.serviceID);
    if (this.extensions != null && !this.extensions.isEmpty()) {
      aci.setAnyList(extensions);
    }

    if (this.attributeMappings != null && !this.attributeMappings.isEmpty()) {
      final IdAttributes ida = new IdAttributes();
      ida.setAttributeMappings(attributeMappings);
      samlAuthContext.setIdAttributes(ida);
    }

    return samlAuthContext;
  }
}
