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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Model for attribute type and value.
 * <p>
 * X.509 certificates include use of both the type "Attribute" and the type "AttributeTypeAndValue" The difference being
 * that the former may have any number of values, while the latter can have only one value.
 * </p>
 * <p>
 * AttributeTypeAndValue is used in Subject name RDNs.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AttributeTypeAndValueModel {

  /** Attribute OID. */
  private ASN1ObjectIdentifier attributeType;

  /** Attribute value. */
  private Object value;

}
