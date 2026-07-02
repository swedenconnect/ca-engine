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
package se.swedenconnect.ca.engine.ca.issuer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Objects;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.issuer.impl.BasicSerialNumberProvider;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;

/**
 * This certificate builder model provides basic configuration data for a {@link CertificateIssuer}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
@Getter
@Slf4j
public class CertificateIssuerModel {

  /** Engine for generating certificate serial numbers */
  @Setter
  private SerialNumberProvider serialNumberProvider = new BasicSerialNumberProvider();

  /** Offset duration for altering the not valid before time of certificates relative to current time */
  @Setter
  private Duration startOffset = Duration.ofSeconds(-15);

  /**
   * Offset duration for setting the not valid after time relative to current time.
   * A value of Duration.ZERO indicates that the certificate should not expire.
   */
  private Duration expiryOffset = Duration.ofDays(365);

  /** The name of the algorithm used by the crypto provider to sign ASN.1 objects */
  private String algorithmName;

  /** The signing algorithm used to sign certificates */
  private String algorithm;

  /** Setting this to true generates V1 certificates if the certificate model lacks extensions */
  @Setter
  private boolean v1 = false;

  /**
   * Constructor for the certificate issuer model.
   *
   * @param algorithm the XML identifier of the certificate signing algorithm
   * @param validity the validity duration of issued certificates
   * @throws NoSuchAlgorithmException thrown if the provided algorithm is not recognized
   */
  public CertificateIssuerModel(final String algorithm, final Duration validity) throws NoSuchAlgorithmException {
    Objects.requireNonNull(algorithm, "algorithm must not be null");
    this.algorithm = algorithm;
    this.algorithmName = CAAlgorithmRegistry.getSigAlgoName(algorithm);
    setExpiryOffset(validity);
  }

  public void setExpiryOffset(final Duration expiryOffset) {
    Objects.requireNonNull(expiryOffset, "expiryOffset must not be null");
    if (expiryOffset.equals(Duration.ZERO)) {
      throw new IllegalArgumentException("Expiry offset cannot be zero");
    }
    this.expiryOffset = expiryOffset;
  }

  public void setInfiniteValidity() {
    this.expiryOffset = Duration.ZERO;
  }

  public boolean isInfiniteValidity() {
    return this.expiryOffset.isZero();
  }

  /**
   * Returns an instance of {@link MessageDigest} specified by the certificate signature algorithm.
   *
   * @return message digest instance
   */
  public MessageDigest getSigAlgoMessageDigest() {
    MessageDigest messageDigestInstance = null;
    try {
      messageDigestInstance = CAAlgorithmRegistry.getMessageDigestInstance(this.algorithm);
    }
    catch (final NoSuchAlgorithmException e) {
      log.error("Illegal configured signature algorithm prevents retrieval of signature algorithm digest algorithm", e);
    }
    return messageDigestInstance;
  }

}
