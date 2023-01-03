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
package se.swedenconnect.ca.engine.ca.models.cert.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import lombok.NoArgsConstructor;
import lombok.Setter;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;

/**
 * The CertName class reflects a complete Name field used in X.509 certificates to define an issuer name or a subject
 * name, or a DistiguishedName field. The difference between Name and DistiguishedName is that Distinguished name is
 * equal to RDNSequence, while Name is a CHOICE, where the only choice is an RDNSequence. As such ,they are equal in
 * practice due to lack of choices for Name.
 *
 * <pre>
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 *
 * AttributeTypeAndValue   ::= SEQUENCE {
 * type    AttributeType,   -- OID
 * value   AttributeValue } -- Any defined by AttributeType
 * </pre>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
public class ExplicitCertNameModel implements CertNameModel<List<List<AttributeTypeAndValueModel>>> {

  /**
   * Relative distinguished name structure
   *
   * @param rdnSequence relative distinguished name structure
   */
  @Setter
  private List<List<AttributeTypeAndValueModel>> rdnSequence;

  /**
   * Constructor for this certificate name model
   *
   * @param attributeList list of attribute type and values
   */
  public ExplicitCertNameModel(final List<AttributeTypeAndValueModel> attributeList) {
    this.rdnSequence = new ArrayList<>();
    for (final AttributeTypeAndValueModel atavModel : attributeList) {
      this.rdnSequence.add(Arrays.asList(atavModel));
    }
  }

  /** {@inheritDoc} */
  @Override
  public CertNameModelType getType() {
    return CertNameModelType.explicit;
  }

  /** {@inheritDoc} */
  @Override
  public List<List<AttributeTypeAndValueModel>> getNameData() {
    return this.rdnSequence;
  }

}
