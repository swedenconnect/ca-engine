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

package se.swedenconnect.ca.engine.ca.models.cert.extension.data;

import org.w3c.dom.Element;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.AttributeMapping;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.AuthContextInfo;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.IdAttributes;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.SAMLAuthContext;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

/**
 * Builder for Authn Context data in the Authn Context extension
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
  public SAMLAuthContextBuilder assertionRef(String assertionRef) {
    this.assertionRef = assertionRef;
    return this;
  }

  /**
   * Set level of assurance
   *
   * @param authnContextClassRef level of assurance
   * @return this builder
   */
  public SAMLAuthContextBuilder authnContextClassRef(String authnContextClassRef) {
    this.authnContextClassRef = authnContextClassRef;
    return this;
  }

  /**
   * Set time of authentication
   *
   * @param authenticationInstant time of authentication
   * @return this builder
   */
  public SAMLAuthContextBuilder authenticationInstant(Date authenticationInstant) {
    this.authenticationInstant = authenticationInstant;
    return this;
  }

  /**
   * Set identity provider
   *
   * @param identityProvider identity provider
   * @return this builder
   */
  public SAMLAuthContextBuilder identityProvider(String identityProvider) {
    this.identityProvider = identityProvider;
    return this;
  }

  /**
   * Set service identifier
   *
   * @param serviceID service identifier
   * @return this builder
   */
  public SAMLAuthContextBuilder serviceID(String serviceID) {
    this.serviceID = serviceID;
    return this;
  }

  /**
   * Set extension
   *
   * @param extensions extensions
   * @return this builder
   */
  public SAMLAuthContextBuilder extensions(List<Element> extensions) {
    this.extensions = extensions;
    return this;
  }

  /**
   * Set attribute mappings
   *
   * @param attributeMappings attribute mappings
   * @return this builder
   */
  public SAMLAuthContextBuilder attributeMappings(List<AttributeMapping> attributeMappings) {
    this.attributeMappings = attributeMappings;
    return this;
  }

  /**
   * Build SAML Authentication context
   *
   * @return {@link SAMLAuthContext}
   */
  public SAMLAuthContext build() {

    SAMLAuthContext samlAuthContext = new SAMLAuthContext();
    AuthContextInfo aci = new AuthContextInfo();
    samlAuthContext.setAuthContextInfo(aci);
    aci.setAssertionRef(assertionRef);
    aci.setAuthenticationInstant(getXmlDate(authenticationInstant));
    aci.setAuthnContextClassRef(authnContextClassRef);
    aci.setIdentityProvider(identityProvider);
    aci.setServiceID(serviceID);
    if (extensions != null && !extensions.isEmpty()) {
      List<Element> elements = aci.getAnies();
      extensions.stream().forEach(element -> elements.add(element));
    }

    if (attributeMappings != null && !attributeMappings.isEmpty()) {
      IdAttributes ida = new IdAttributes();
      samlAuthContext.setIdAttributes(ida);
      List<AttributeMapping> atrMapList = ida.getAttributeMappings();
      attributeMappings.stream().forEach(attributeMapping -> atrMapList.add(attributeMapping));
    }

    return samlAuthContext;
  }

  /**
   * Convert {@link Date} to {@link XMLGregorianCalendar}
   * @param date date to convert
   * @return {@link XMLGregorianCalendar}
   * @throws CertificateIssuanceException error parsing date
   */
  public static XMLGregorianCalendar getXmlDate(Date date) throws CertificateIssuanceException {
    GregorianCalendar gcal = new GregorianCalendar();
    gcal.setTime(date);
    try {
      return DatatypeFactory.newInstance().newXMLGregorianCalendar(gcal);
    }
    catch (DatatypeConfigurationException e) {
      throw new CertificateIssuanceException("Illegal date", e);
    }
  }

}
