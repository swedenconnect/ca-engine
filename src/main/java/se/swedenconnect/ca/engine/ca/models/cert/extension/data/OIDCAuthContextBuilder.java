/*
 * Copyright 2026 Sweden Connect
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

import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.cert.extensions.data.oaci.ClaimMapping;
import se.swedenconnect.cert.extensions.data.oaci.OIDCAuthContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.JsonNodeFactory;

/**
 * Builder for OpenID Connect Authentication Context Information (OACI) in the Authn Context extension.
 * <p>
 * The built object is validated against the content rules of draft-santesson-oidc-cert-auth-context. Requirements of
 * a deployment profile, such as which members must be present, are the responsibility of the caller.
 * </p>
 *
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)
 */
public class OIDCAuthContextBuilder {

  /**
   * Private constructor
   */
  private OIDCAuthContextBuilder() {
  }

  /**
   * Creates an instance of this {@link OIDCAuthContextBuilder}
   *
   * @return {@link OIDCAuthContextBuilder}
   */
  public static OIDCAuthContextBuilder instance() {
    return new OIDCAuthContextBuilder();
  }

  /** Issuer Identifier of the OpenID Provider */
  private String iss;

  /** Time of authentication */
  private Instant authTime;

  /** Authentication Context Class Reference */
  private String acr;

  /** Authentication Methods References */
  private List<String> amr;

  /** ID Token identifier */
  private String jti;

  /** Subject Identifier at the OpenID Provider */
  private String sub;

  /** Client identifier of the Relying Party */
  private String clientId;

  /** Claim mappings */
  private List<ClaimMapping> claimMappings;

  /** Additional members, in insertion order */
  private final Map<String, JsonNode> additionalMembers = new LinkedHashMap<>();


  /**
   * Set the Issuer Identifier of the OpenID Provider ({@code iss})
   *
   * @param iss issuer identifier
   * @return this builder
   */
  public OIDCAuthContextBuilder iss(final String iss) {
    this.iss = iss;
    return this;
  }

  /**
   * Set the time of authentication ({@code auth_time}), stored with whole second precision
   *
   * @param authTime time of authentication
   * @return this builder
   */
  public OIDCAuthContextBuilder authTime(final Instant authTime) {
    this.authTime = authTime;
    return this;
  }

  /**
   * Set the Authentication Context Class Reference ({@code acr})
   *
   * @param acr authentication context class reference
   * @return this builder
   */
  public OIDCAuthContextBuilder acr(final String acr) {
    this.acr = acr;
    return this;
  }

  /**
   * Set the Authentication Methods References ({@code amr})
   *
   * @param amr authentication methods references
   * @return this builder
   */
  public OIDCAuthContextBuilder amr(final List<String> amr) {
    this.amr = amr;
    return this;
  }

  /**
   * Set the ID Token identifier ({@code jti})
   *
   * @param jti ID Token identifier
   * @return this builder
   */
  public OIDCAuthContextBuilder jti(final String jti) {
    this.jti = jti;
    return this;
  }

  /**
   * Set the Subject Identifier of the End-User at the OpenID Provider ({@code sub})
   *
   * @param sub subject identifier
   * @return this builder
   */
  public OIDCAuthContextBuilder sub(final String sub) {
    this.sub = sub;
    return this;
  }

  /**
   * Set the client identifier under which the Relying Party acted towards the OpenID Provider ({@code client_id})
   *
   * @param clientId client identifier
   * @return this builder
   */
  public OIDCAuthContextBuilder clientId(final String clientId) {
    this.clientId = clientId;
    return this;
  }

  /**
   * Set the claim mappings ({@code claim_mappings})
   *
   * @param claimMappings claim mappings
   * @return this builder
   */
  public OIDCAuthContextBuilder claimMappings(final List<ClaimMapping> claimMappings) {
    this.claimMappings = claimMappings;
    return this;
  }

  /**
   * Add a member that is not defined by the specification, for example a member defined by a deployment profile
   *
   * @param name member name, which MUST NOT be one of the member names defined by the specification and MUST NOT
   *          have been added before
   * @param value JSON value of the member
   * @return this builder
   * @throws IllegalArgumentException if the name is a defined member name or has already been added
   */
  public OIDCAuthContextBuilder additionalMember(final String name, final JsonNode value) {
    if (name == null || name.isEmpty()) {
      throw new IllegalArgumentException("Additional member name must not be empty");
    }
    if (OIDCAuthContext.DEFINED_MEMBERS.contains(name)) {
      throw new IllegalArgumentException("Additional member name collides with a defined member: " + name);
    }
    if (this.additionalMembers.containsKey(name)) {
      throw new IllegalArgumentException("Additional member already added: " + name);
    }
    if (value == null) {
      throw new IllegalArgumentException("Additional member value must not be null");
    }
    this.additionalMembers.put(name, value);
    return this;
  }

  /**
   * Add an additional member with a string value, see {@link #additionalMember(String, JsonNode)}
   *
   * @param name member name
   * @param value string value
   * @return this builder
   */
  public OIDCAuthContextBuilder additionalMember(final String name, final String value) {
    return this.additionalMember(name, JsonNodeFactory.instance.textNode(value));
  }

  /**
   * Add an additional member with a numeric value, see {@link #additionalMember(String, JsonNode)}
   *
   * @param name member name
   * @param value numeric value
   * @return this builder
   */
  public OIDCAuthContextBuilder additionalMember(final String name, final long value) {
    return this.additionalMember(name, JsonNodeFactory.instance.numberNode(value));
  }

  /**
   * Add an additional member with a boolean value, see {@link #additionalMember(String, JsonNode)}
   *
   * @param name member name
   * @param value boolean value
   * @return this builder
   */
  public OIDCAuthContextBuilder additionalMember(final String name, final boolean value) {
    return this.additionalMember(name, JsonNodeFactory.instance.booleanNode(value));
  }

  /**
   * Build OpenID Connect Authentication Context Information
   *
   * @return {@link OIDCAuthContext}
   * @throws CertificateIssuanceException if the built object violates the content rules of the specification
   */
  public OIDCAuthContext build() throws CertificateIssuanceException {
    final OIDCAuthContext oidcAuthContext = OIDCAuthContext.builder()
      .iss(this.iss)
      .acr(this.acr)
      .amr(this.amr == null || this.amr.isEmpty() ? null : List.copyOf(this.amr))
      .jti(this.jti)
      .sub(this.sub)
      .clientId(this.clientId)
      .claimMappings(
        this.claimMappings == null || this.claimMappings.isEmpty() ? null : List.copyOf(this.claimMappings))
      .additionalMembers(this.additionalMembers.isEmpty() ? null : new LinkedHashMap<>(this.additionalMembers))
      .build();
    oidcAuthContext.setAuthTimeInstant(this.authTime);
    try {
      oidcAuthContext.validate(true);
    }
    catch (final CertificateException e) {
      throw new CertificateIssuanceException("Invalid OpenID Connect authentication context: " + e.getMessage(), e);
    }
    return oidcAuthContext;
  }
}
