/*
 * Copyright 2024 Agency for Digital Government (DIGG)
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

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500NameStyle;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

/**
 * This class provides an attribute value encoder for encoding arbitrary attribute data to ASN.1 value objects in X.509
 * certificate attributes.
 *
 * <p>
 * This class builds on an existing encoder implementing the {@link X500NameStyle} interface. By default the
 * {@link CertAttributes} implementation is used.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
@AllArgsConstructor
public class AttributeValueEncoder {

  /** The attribute value encoder used by this class */
  public X500NameStyle encoder = new CertAttributes();

  /** Date with hyphen regex */
  public static final String DATE_SIMPLE_FOMRAT_REGEX_HYPHEN = "^(19|20)[0-9]{2}-[0-9]{2}-[0-9]{2}$";

  /** Simple Date regex */
  public static final String DATE_SIMPLE_FOMRAT_REGEX = "^(19|20)[0-9]{6}$";

  /** Simple date format */
  public static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");

  /**
   * Assigns an attribute value encoder
   *
   * @param encoder Attribute value encoder
   */
  public void setEncoder(final X500NameStyle encoder) {
    this.encoder = encoder;
  }

  /**
   * Encode the attribute value from string to an ASN.1 object.
   *
   * <p>
   * The exact semantics of the input and the encoded result is determined by the registered attribute encoder.
   * </p>
   * <p>
   * The default encoder follows the following rules
   * </p>
   * <ul>
   * <li>The attributes e-mail address and domain component are encoded as IA5String</li>
   * <li>The attribute serialNumber is encoded as printableString if all characters are compatible with printable
   * string, else it is encoded as UTF8String (in violation with X520, but generally accepted)</li>
   * <li>Country and DNQualifier are encoded as printableString</li>
   * <li>DateOfBirth is using the format YYYMMDD, e.g. for 1952-10-05 specify 19521005 and encodes this as
   * GeneralizedTime</li>
   * </ul>
   *
   * @param oid ASN.1 Object Identifier
   * @param value String value representation of the attribute value.
   * @return ASN.1 object holding the attribute value
   * @throws IOException encoding error
   */
  public ASN1Encodable encode(final ASN1ObjectIdentifier oid, final Object value) throws IOException {

    // If the value is a String value, then copy this to the input string
    String strValue = value instanceof String ? (String) value : null;

    // The only case where a non String value is allowed is a Date object provided as Date of Birth
    if (oid.equals(CertAttributes.DATE_OF_BIRTH)) {
      if (value instanceof Date) {
        // Convert the date to a normalized date, using just the YYYYMMDD date information as noon GMT
        strValue = dateFormat.format((Date) value) + "120000Z";
      }
      if (value instanceof String) {
        // If simplified input is used (YYYY-MM-DD or YYYYMMDD) then convert to normalized date string noon GMT
        if (strValue != null && strValue.matches(DATE_SIMPLE_FOMRAT_REGEX_HYPHEN)
            || strValue.matches(DATE_SIMPLE_FOMRAT_REGEX)) {
          strValue = strValue.replaceAll("-", "") + "120000Z";
        }
        // Otherwise trust that the input string value is correct as it is. Make no attempts to modify it.
      }
    }
    // At this point we require a non null string value
    if (strValue == null) {
      throw new IOException("Illegal date input data: " + value);
    }

    try {
      // Use the current encoder to encode the value as attribute value based on the input string
      return this.encoder.stringToValue(oid, strValue);
    }
    catch (final Exception ex) {
      throw new IOException("Failed to encode attribute value for type " + oid.getId() + " and value " + value, ex);
    }
  }

}
