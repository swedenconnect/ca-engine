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

package se.swedenconnect.ca.engine.ca.models.cert;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.Arrays;
import java.util.List;

/**
 * Attribute               ::= SEQUENCE {
 * type             AttributeType,
 * values    SET OF AttributeValue }
 * -- at least one value is required
 * <p>
 * AttributeType           ::= OBJECT IDENTIFIER
 * AttributeValue          ::= ANY -- DEFINED BY AttributeType
 * <p>
 * X.509 certificates include use of both the type "Attribute" and
 * the type "AttributeTypeAndValue" The difference being that the former
 * may have any number of values, while the latter can have only one value.
 * <p>
 * Attribute is used in SubjectDirectoryAttributes extension
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AttributeModel {

  /**
   * Constructor
   *
   * @param attributeType attribute OID
   * @param value         attribute values
   */
  public AttributeModel(ASN1ObjectIdentifier attributeType, Object... value) {
    this.attributeType = attributeType;
    this.valueList = Arrays.asList(value);
  }

  /** Attribute OID */
  private ASN1ObjectIdentifier attributeType;
  /** List of attribute values */
  private List<Object> valueList;
}
