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
package se.swedenconnect.ca.engine.ca.models.cert;

import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * <pre>
 *   Attribute ::= SEQUENCE {
 *     type             AttributeType,
 *     values    SET OF AttributeValue }
 *   -- at least one value is required
 * </pre>
 * <pre>
 * AttributeType  ::= OBJECT IDENTIFIER
 * AttributeValue ::= ANY -- DEFINED BY AttributeType
 * </pre>
 * <p>
 * X.509 certificates include use of both the type "Attribute" and the type "AttributeTypeAndValue" The difference being
 * that the former may have any number of values, while the latter can have only one value.
 * </p>
 * <p>
 * Attribute is used in SubjectDirectoryAttributes extension.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AttributeModel {

  /** Attribute OID. */
  private ASN1ObjectIdentifier attributeType;

  /** List of attribute values. */
  private List<Object> valueList;

  /**
   * Constructor.
   *
   * @param attributeType attribute OID
   * @param value attribute values
   */
  public AttributeModel(final ASN1ObjectIdentifier attributeType, final Object... value) {
    this.attributeType = attributeType;
    this.valueList = Arrays.asList(value);
  }

}
