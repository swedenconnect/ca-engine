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
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.issuer.impl.BasicSerialNumberProvider;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;

/**
 * This certificate builder model provides basic configuration data for a {@link CertificateIssuer}
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
@Getter
@Slf4j
public class CertificateIssuerModel {

  /** Engine for generating certificate serial numbers */
  @Setter private SerialNumberProvider serialNumberProvider = new BasicSerialNumberProvider();
  /** Offset type for altering the not valid before time of certificates relative to current time */
  @Setter private int startOffsetType = Calendar.MINUTE;
  /** Offset amount for altering the not valid before time of certificates where a negative value indicated before current time */
  @Setter private int startOffsetAmount = -15;
  /** Offset type for setting the not valid after time relative to current time */
  @Setter private int expiryOffsetType = Calendar.YEAR;
  /** Offset amount defining the validity time of issued certificates */
  private int expiryOffsetAmount = 1;
  /** The name of the algorithm used by the crypto provider to sign ASN.1 objects */
  private String algorithmName;
  /** The signing algorithm used to sign certificates */
  private String algorithm;
  /** Setting this to true generates V1 certificates if the certificate model lacks extensions */
  @Setter private boolean v1 = false;

  /**
   * Constructor for the certificate issuer model
   *
   * @param algorithm  the XML identifier of the certificate signing algorithm
   * @param validYears the number of years the issued certificates should be valid
   * @throws NoSuchAlgorithmException thrown if the provided algorithm is not recognized
   */
  public CertificateIssuerModel(String algorithm, int validYears) throws NoSuchAlgorithmException {
    this.algorithm = algorithm;
    this.algorithmName = CAAlgorithmRegistry.getSigAlgoName(algorithm);
    this.expiryOffsetAmount = validYears;
  }

  /**
   * Constructor for the certificate builder model
   *
   * @param algorithm          the XML identifier of the certificate signing algorithm
   * @param expiryOffsetAmount the amount of time units issued certificates should be valid
   * @param expiryOffsetType   the type of time unit for certificate validity time defined as the {@link Calendar} integer constant of time
   *                           unit type (e.g. Calendar.YEAR)
   * @throws NoSuchAlgorithmException unsupported algorithm
   */
  public CertificateIssuerModel(String algorithm, int expiryOffsetAmount, int expiryOffsetType)
    throws NoSuchAlgorithmException {
    this(algorithm, expiryOffsetAmount);
    this.expiryOffsetType = expiryOffsetType;
  }

  /**
   * Returns an instance of {@link MessageDigest} specified by the certificate signature algorithm
   *
   * @return message digest instance
   */
  public MessageDigest getSigAlgoMessageDigest() {
    MessageDigest messageDigestInstance = null;
    try {
      messageDigestInstance = CAAlgorithmRegistry.getMessageDigestInstance(algorithm);
    }
    catch (NoSuchAlgorithmException e) {
      log.error("Illegal configured signature algorithm prevents retrieval of signature algorithm digest algorithm", e);
    }
    return messageDigestInstance;
  }

}
