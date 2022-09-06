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
package se.swedenconnect.ca.engine.ca.models.cert.extension.data;

import java.math.BigInteger;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import se.swedenconnect.cert.extensions.QCStatements;
import se.swedenconnect.cert.extensions.data.MonetaryValue;
import se.swedenconnect.cert.extensions.data.PDSLocation;

/**
 * Builder for QC statements.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class QcStatementsBuilder {

  private QCPKIXSyntax versionAndSemantics;
  private boolean qualifiedCertificate = false;
  private boolean qscd = false;
  private List<ASN1ObjectIdentifier> qcTypes;
  private List<String> legislationCountries;
  private MonetaryValue relianceLimit;
  private Integer retentionPeriod;
  private List<PDSLocation> pdsLocations;

  /**
   * Gets an instance of the QC Statements builder.
   *
   * @return {@link QcStatementsBuilder}
   */
  public static QcStatementsBuilder instance() {
    return new QcStatementsBuilder();
  }

  /**
   * Private constructor.
   */
  private QcStatementsBuilder() {
  }

  /**
   * Set version and semantics.
   *
   * @param versionAndSemantics version and semantics
   * @return this builder
   */
  public QcStatementsBuilder versionAndSemantics(final QCPKIXSyntax versionAndSemantics) {
    this.versionAndSemantics = versionAndSemantics;
    return this;
  }

  /**
   * Set qualified certificate status
   *
   * @param qualifiedCertificate qualified certificate status
   * @return this builder
   */
  public QcStatementsBuilder qualifiedCertificate(final boolean qualifiedCertificate) {
    this.qualifiedCertificate = qualifiedCertificate;
    return this;
  }

  /**
   * Set qualified signature creation device status
   *
   * @param qscd qualified signature creation device status
   * @return this builder
   */
  public QcStatementsBuilder qscd(final boolean qscd) {
    this.qscd = qscd;
    return this;
  }

  /**
   * Set qualified certificate certificate types
   *
   * @param qcTypes qualified certificate certificate types
   * @return this builder
   */
  public QcStatementsBuilder qcTypes(final List<ASN1ObjectIdentifier> qcTypes) {
    this.qcTypes = qcTypes;
    return this;
  }

  /**
   * Set legislation countries
   *
   * @param legislationCountries legislation countries
   * @return this builder
   */
  public QcStatementsBuilder legislationCountries(final List<String> legislationCountries) {
    this.legislationCountries = legislationCountries;
    return this;
  }

  /**
   * Set reliance limit
   *
   * @param relianceLimit reliance limit
   * @return this builder
   */
  public QcStatementsBuilder relianceLimit(final MonetaryValue relianceLimit) {
    this.relianceLimit = relianceLimit;
    return this;
  }

  /**
   * Set retention period
   *
   * @param retentionPeriod retention period
   * @return this builder
   */
  public QcStatementsBuilder retentionPeriod(final Integer retentionPeriod) {
    this.retentionPeriod = retentionPeriod;
    return this;
  }

  /**
   * Set PDS locations
   *
   * @param pdsLocations PDS locations
   * @return this builder
   */
  public QcStatementsBuilder pdsLocations(final List<PDSLocation> pdsLocations) {
    this.pdsLocations = pdsLocations;
    return this;
  }

  /**
   * Builds a QCStatements extension object
   *
   * @return {@link QCStatements}
   */
  public QCStatements build() {

    final QCStatements qcStatements = new QCStatements();

    if (this.versionAndSemantics != null) {
      switch (this.versionAndSemantics.getVersion()) {
      case V1:
        qcStatements.setPkixSyntaxV1(true);
        break;
      case V2:
        qcStatements.setPkixSyntaxV2(true);
        break;
      }
      qcStatements.setSemanticsInfo(this.versionAndSemantics.getSemanticsInformation());
    }

    if (this.qualifiedCertificate) {
      qcStatements.setQcCompliance(true);
    }
    if (this.qscd) {
      qcStatements.setQcSscd(true);
    }

    if (this.qcTypes != null && !this.qcTypes.isEmpty()) {
      qcStatements.setQcType(true);
      qcStatements.setQcTypeIdList(this.qcTypes);
    }

    if (this.legislationCountries != null && !this.legislationCountries.isEmpty()) {
      qcStatements.setQcCClegislation(true);
      qcStatements.setLegislationCountryList(this.legislationCountries);
    }

    if (this.relianceLimit != null) {
      qcStatements.setLimitValue(true);
      qcStatements.setMonetaryValue(this.relianceLimit);
    }

    if (this.retentionPeriod != null) {
      qcStatements.setRetentionPeriod(true);
      qcStatements.setRetentionPeriodVal(new BigInteger(String.valueOf(this.retentionPeriod)));
    }

    if (this.pdsLocations != null && !this.pdsLocations.isEmpty()) {
      qcStatements.setPdsStatement(true);
      qcStatements.setLocationList(this.pdsLocations);
    }
    return qcStatements;
  }

}
