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

package se.swedenconnect.ca.engine.ca.models.cert.impl;

import lombok.*;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The CertName class reflects a complete Name field used in X.509 certificates to define an issuer name or a subject name, or
 * a DistiguishedName field. The difference between Name and DistiguishedName is that Distinguished name is equal to RDNSequence, while
 * Name is a CHOICE, where the only choice is an RDNSequence. As such ,they are equal in practice due to lack of choices for Name.
 * <p>
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 * <p>
 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 * <p>
 * AttributeTypeAndValue   ::= SEQUENCE {
 * type    AttributeType,   -- OID
 * value   AttributeValue } -- Any defined by AttributeType
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
public class ExplicitCertNameModel implements CertNameModel<List<List<AttributeTypeAndValueModel>>> {

  @Setter private List<List<AttributeTypeAndValueModel>> rdnSequence;

  public ExplicitCertNameModel(List<AttributeTypeAndValueModel> attributeList) {
    this.rdnSequence = new ArrayList<>();
    for (AttributeTypeAndValueModel atavModel : attributeList) {
      rdnSequence.add(Arrays.asList(atavModel));
    }
  }

  @Override public CertNameModelType getType() {
    return CertNameModelType.explicit;
  }

  @Override public List<List<AttributeTypeAndValueModel>> getNameData() {
    return rdnSequence;
  }

}
