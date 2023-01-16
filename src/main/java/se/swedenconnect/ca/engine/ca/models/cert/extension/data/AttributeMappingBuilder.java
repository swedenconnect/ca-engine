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
package se.swedenconnect.ca.engine.ca.models.cert.extension.data;

import se.swedenconnect.cert.extensions.data.saci.AttributeMapping;
import se.swedenconnect.cert.extensions.data.saci.SAMLAttribute;

/**
 * Builder for attribute mappings used in SAML Authn context extensions.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AttributeMappingBuilder {

  /** Identifier of the mapped attribute e.g. SAML name. */
  private String name;

  /** Friendly name of the mapped attribute. */
  private String friendlyName;

  /** The name format of the mapped attribute. */
  private String nameFormat;

  /** Reference id defining the target certificate attribute or name. */
  private String ref;

  /** Type identifier defining the type of certificate name or attribute. */
  private AttributeMapping.Type type;

  /** Private constructor */
  private AttributeMappingBuilder() {
  }

  /**
   * Creates a new {@link AttributeMappingBuilder}
   *
   * @return an AttributeMappingBuilder
   */
  public static AttributeMappingBuilder instance() {
    return new AttributeMappingBuilder();
  }

  /**
   * Sets source attribute identifier.
   *
   * @param name identifier of the source attribute
   * @return this builder
   */
  public AttributeMappingBuilder name(final String name) {
    this.name = name;
    return this;
  }

  /**
   * Set attribute friendly name.
   *
   * @param friendlyName attribute friendly name
   * @return this builder
   */
  public AttributeMappingBuilder friendlyName(final String friendlyName) {
    this.friendlyName = friendlyName;
    return this;
  }

  /**
   * Set nameFormat.
   *
   * @param nameFormat nameFormat of source attribute
   * @return this builder
   */
  public AttributeMappingBuilder nameFormat(final String nameFormat) {
    this.nameFormat = nameFormat;
    return this;
  }

  /**
   * Set certificate attribute reference.
   *
   * @param ref reference for the relevant type (rdn, san or sad)
   * @return this builder
   */
  public AttributeMappingBuilder ref(final String ref) {
    this.ref = ref;
    return this;
  }

  /**
   * Set certificate reference type
   *
   * @param type rdn (Relative Distinguished Name), san (Subject Alt Name) or sda (Subject Directory Attributes)
   * @return this builder
   */
  public AttributeMappingBuilder type(final AttributeMapping.Type type) {
    this.type = type;
    return this;
  }

  /**
   * Create attribute mapping
   *
   * @return attribute mapping
   */
  public AttributeMapping build() {
    final AttributeMapping am = new AttributeMapping();
    final SAMLAttribute attribute = new SAMLAttribute();
    attribute.setFriendlyName(this.friendlyName);
    attribute.setName(this.name);
    attribute.setNameFormat(this.nameFormat);
    am.setAttribute(attribute);
    am.setRef(this.ref);
    am.setType(this.type);
    return am;
  }

}
