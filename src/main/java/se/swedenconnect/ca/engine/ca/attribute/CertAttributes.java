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

package se.swedenconnect.ca.engine.ca.attribute;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * Certificate attribute encoder extending the {@link BCStyle} encoder
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CertAttributes extends BCStyle {

  /**
   * Provides a static instance this class
   */
  public static final CertAttributes INSTANCE = new CertAttributes();

  /**
   * The Swedish person identifier attribute
   */
  public static final ASN1ObjectIdentifier PERSONAL_IDENTITY_NUMBER_SE = new ASN1ObjectIdentifier("1.2.752.29.4.13");

  /**
   * Regular expression for testing if a string can be encoded as PrintableString
   */
  public static final String PRINTABLE_STRING_REGEX = "^[a-zA-Z0-9'\\(\\)+\\,\\-\\.\\?:\\/=\\ ]{1,}$";

  /**
   * Constructor
   */
  protected CertAttributes() {
    super();
    //defaultLookUp.put("personalIdentityNumber", PERSONAL_IDENTITY_NUMBER_SE);
    //defaultSymbols.put(PERSONAL_IDENTITY_NUMBER_SE, "personalIdentityNumber");
  }

  /**
   * Encode a string value input to a suitable ASN.1 object based on attribute type
   *
   * @param oid   attribute type OID
   * @param value string value
   * @return ASN.1 encoded value
   */
  @Override protected ASN1Encodable encodeStringValue(ASN1ObjectIdentifier oid, String value) {

    // Adding encoding rules for the SE personal identifier attribute
    if (oid.equals(PERSONAL_IDENTITY_NUMBER_SE) && value.matches(PRINTABLE_STRING_REGEX)) {
      return new DERPrintableString(value);
    }

    // Provide custom rules for serialNumber
    if (oid.equals(SERIALNUMBER)) {
      // For serialNumber we use printable string only if the value is consistent with printable string syntax
      if (value.matches(PRINTABLE_STRING_REGEX)) {
        return new DERPrintableString(value);
      }
      // For all other cases we are forced to use UTF8String syntax. This is not compatible with X.520, but it is generally acceptable
      return new DERUTF8String(value);
    }

    // For all other attributes, use standard encoding
    return super.encodeStringValue(oid, value);
  }
}
