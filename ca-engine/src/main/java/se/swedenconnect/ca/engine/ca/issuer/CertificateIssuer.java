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

package se.swedenconnect.ca.engine.ca.issuer;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.ca.attribute.AttributeValueEncoder;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.EncodedCertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.utils.CAUtils;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * Abstract class for a certificate issuer component.
 * <p>
 * The certificate issuer component is responsible for crafting X.509 certificates for a CA service
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class CertificateIssuer {

  /** Configuration data for a certificate issuer component */
  @Getter protected final CertificateIssuerModel certificateIssuerModel;
  /** Encoder for encoding attribute values */
  @Setter protected final AttributeValueEncoder attributeValueEncoder = new AttributeValueEncoder();

  /**
   * Constructor for the certificate issuer
   *
   * @param certificateIssuerModel configuration data for the certificate issuer component
   */
  public CertificateIssuer(CertificateIssuerModel certificateIssuerModel) {
    this.certificateIssuerModel = certificateIssuerModel;
  }

  /**
   * Issue a certificate
   *
   * @param model model specifying the content of the certificate to issue
   * @return issued certificate
   * @throws CertificateIssuanceException error issuing the certificate based on the provided model
   */
  public abstract X509CertificateHolder issueCertificate(CertificateModel model) throws CertificateIssuanceException;

  /**
   * Utility function creating a X500Name object based on a certificate name model
   *
   * @param nameModel certificate name model holding information about a certificate name
   * @return X500Name object
   * @throws IOException errors creating the X500Name object
   */
  protected X500Name getX500Name(CertNameModel nameModel) throws IOException {
    return CAUtils.getX500Name(nameModel, attributeValueEncoder);
  }

  /**
   * Utility function calculating the offset time based on offset type and amount
   *
   * @param offsetType   offset type
   * @param offsetAmount offset amount of the specified type
   * @return new time with specified offset from current time
   */
  public static Date getOffsetTime(int offsetType, int offsetAmount) {
    Calendar offsetTime = Calendar.getInstance();
    offsetTime.setTime(new Date());
    offsetTime.add(offsetType, offsetAmount);
    return offsetTime.getTime();
  }

}
