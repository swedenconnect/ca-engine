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

  private String assertionRef;

  private String authnContextClassRef;

  private Date authenticationInstant;

  private String identityProvider;

  private String serviceID;

  private List<Element> extensions;

  private List<AttributeMapping> attributeMappings;

  public SAMLAuthContextBuilder assertionRef(String assertionRef) {
    this.assertionRef = assertionRef;
    return this;
  }

  public SAMLAuthContextBuilder authnContextClassRef(String authnContextClassRef) {
    this.authnContextClassRef = authnContextClassRef;
    return this;
  }

  public SAMLAuthContextBuilder authenticationInstant(Date authenticationInstant) {
    this.authenticationInstant = authenticationInstant;
    return this;
  }

  public SAMLAuthContextBuilder identityProvider(String identityProvider) {
    this.identityProvider = identityProvider;
    return this;
  }

  public SAMLAuthContextBuilder serviceID(String serviceID) {
    this.serviceID = serviceID;
    return this;
  }

  public SAMLAuthContextBuilder extensions(List<Element> extensions) {
    this.extensions = extensions;
    return this;
  }

  public SAMLAuthContextBuilder attributeMappings(List<AttributeMapping> attributeMappings) {
    this.attributeMappings = attributeMappings;
    return this;
  }

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
