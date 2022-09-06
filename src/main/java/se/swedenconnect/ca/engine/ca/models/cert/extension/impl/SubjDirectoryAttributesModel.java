/*
 * Copyright (c) 2021-2022. Agency for Digital Government (DIGG)
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
package se.swedenconnect.ca.engine.ca.models.cert.extension.impl;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;

import lombok.Setter;
import se.swedenconnect.ca.engine.ca.attribute.AttributeValueEncoder;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.AbstractExtensionModel;

/**
 * Model for subject directory attributes.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SubjDirectoryAttributesModel extends AbstractExtensionModel {

  @Setter
  private AttributeValueEncoder attributeValueEncoder = new AttributeValueEncoder();

  private final List<AttributeModel> attributeList;

  /**
   * Constructor
   *
   * @param attributeList list of attribute data
   */
  public SubjDirectoryAttributesModel(final List<AttributeModel> attributeList) {
    this.attributeList = attributeList;
  }

  @Override
  protected ExtensionMetadata getExtensionMetadata() {
    return new ExtensionMetadata(Extension.subjectDirectoryAttributes, "Subject directory attributes", false);
  }

  @Override
  protected ASN1Object getExtensionObject() throws CertificateIssuanceException {

    if (this.attributeList == null || this.attributeList.isEmpty()) {
      throw new CertificateIssuanceException("At least one attribute must be provided");
    }

    final ASN1EncodableVector attributeSeq = new ASN1EncodableVector();
    for (final AttributeModel am : this.attributeList) {
      final List<Object> valueList = am.getValueList();
      if (am.getAttributeType() == null) {
        throw new CertificateIssuanceException("Null attribute OID");
      }
      if (valueList == null || valueList.isEmpty()) {
        throw new CertificateIssuanceException(
            "At least one value must be present for attribute " + am.getAttributeType().getId());
      }
      final ASN1EncodableVector valueSet = new ASN1EncodableVector();
      for (final Object value : valueList) {
        try {
          final ASN1Encodable encodedVal = this.attributeValueEncoder.encode(am.getAttributeType(), value);
          valueSet.add(encodedVal);
        }
        catch (final IOException e) {
          throw new CertificateIssuanceException("Illegal attribute value", e);
        }
      }

      final Attribute attribute = new Attribute(am.getAttributeType(), new DERSet(valueSet));
      attributeSeq.add(attribute);
    }
    return new DERSequence(attributeSeq);
  }
}
