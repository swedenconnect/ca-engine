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
package se.swedenconnect.ca.engine.revocation.crl;

import java.time.Duration;

import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.cert.X509CertificateHolder;

import lombok.Getter;
import lombok.Setter;

/**
 * Model holding configuration data for a CRL issuer.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public class CRLIssuerModel {

  /** Issuer certificate of the CRL issuer */
  private final X509CertificateHolder issuerCertificate;

  /** Algorithm used to sign CRLs */
  private final String algorithm;

  /** The distribution point URL for this CRL (null if the CRL is published on multiple locations) */
  private final String distributionPointUrl;

  /** Offset duration for altering revocation time from current time */
  @Setter
  private Duration startOffset = Duration.ofMinutes(-15);

  /** Time duration for defining CRL next update time */
  @Setter
  private Duration expiryOffset;

  /** true to mark that the CRL only contains EE certificates */
  @Setter
  private boolean onlyEECerts = false;

  /** true ot mark that the CRL only contains CA certificates */
  @Setter
  private boolean onlyCACerts = false;

  /** Specifies that the CRL only supports the specified reasons */
  @Setter
  private ReasonFlags onlySomeReasons = null;

  /** true if this is an indirect CRL */
  @Setter
  private boolean indirectCrl = false;

  /**
   * When a CRL is created, a new CRL will be created if the latest issued CRL is older than this duration
   * or else a CRL with a copy of the previous stats will be created (CRL number, issue time, next update
   */
  @Setter
  private Duration maxDurationBeforeCRLUpgrade = Duration.ofSeconds(60);


  /**
   * Constructs a CRL issuer model. The number of validity hours can be overwritten with a more suitable type and amount
   * by setting expiryOffsetType and expiryOffsetAmount. E.g. if the "validHours" parameter here is set to 1 and
   * expirtyOffsetType is changed to Calendar.YEAR, then the CRL will expire in 1 year.
   *
   * <p>
   * Note also that one CRLIssuerModel will issue just one CRL at one publication location. If other CRL:s are issued to
   * other locations, they need their own CRL issuer model. This is because the CRLDP location is written into each CRL.
   * </p>
   *
   * @param issuerCertificate issuer certificates of the CRL issuing CA
   * @param algorithm CRL signing algorithm
   * @param validityDuration the duration a CRL is valid
   * @param distributionPointUrl the URL where the URL will be published
   */
  public CRLIssuerModel(
    final X509CertificateHolder issuerCertificate, final String algorithm, final Duration validityDuration,
    final String distributionPointUrl) {
    this.issuerCertificate = issuerCertificate;
    this.expiryOffset = validityDuration;
    this.algorithm = algorithm;
    this.distributionPointUrl = distributionPointUrl;
  }

  /**
   * Constructs a CRL issuer model. The number of validity hours can be overwritten with a more suitable type and amount
   * by setting expiryOffsetType and expiryOffsetAmount. E.g. if the "validHours" parameter here is set to 1 and
   * expirtyOffsetType is changed to Calendar.YEAR, then the CRL will expire in 1 year.
   *
   * <p>
   * Note also that one CRLIssuerModel will issue just one CRL at one publication location. If other CRL:s are issued to
   * other locations, they need their own CRL issuer model. This is because the CRLDP location is written into each CRL.
   * </p>
   *
   * @param issuerCertificate issuer certificates of the CRL issuing CA
   * @param algorithm CRL signing algorithm
   * @param validityDuration the duration a CRL is valid
   * @param distributionPointUrl the URL where the URL will be published
   * @param maxDurationBeforeCRLUpgrade aximum time after CRL issuance when issuance of a new CRL will be enforced
   * (regardless of next Update declaration)
   */
  public CRLIssuerModel(
    final X509CertificateHolder issuerCertificate, final String algorithm, final Duration validityDuration,
    final String distributionPointUrl,  Duration maxDurationBeforeCRLUpgrade) {
    this.issuerCertificate = issuerCertificate;
    this.expiryOffset = validityDuration;
    this.algorithm = algorithm;
    this.distributionPointUrl = distributionPointUrl;
    this.maxDurationBeforeCRLUpgrade = maxDurationBeforeCRLUpgrade;
  }

}
