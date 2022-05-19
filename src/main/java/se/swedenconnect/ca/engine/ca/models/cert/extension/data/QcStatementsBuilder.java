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

package se.swedenconnect.ca.engine.ca.models.cert.extension.data;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import se.swedenconnect.cert.extensions.QCStatements;
import se.swedenconnect.cert.extensions.data.MonetaryValue;
import se.swedenconnect.cert.extensions.data.PDSLocation;

import java.math.BigInteger;
import java.util.List;

/**
 * Builder for QC statements
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
   * Gets an instance of the QC Statements builder
   *
   * @return {@link QcStatementsBuilder}
   */
  public static QcStatementsBuilder instance() {
    return new QcStatementsBuilder();
  }

  /**
   * Private constructor
   */
  private QcStatementsBuilder() {
  }

  public QcStatementsBuilder versionAndSemantics(QCPKIXSyntax versionAndSemantics) {
    this.versionAndSemantics = versionAndSemantics;
    return this;
  }

  public QcStatementsBuilder qualifiedCertificate(boolean qualifiedCertificate) {
    this.qualifiedCertificate = qualifiedCertificate;
    return this;
  }

  public QcStatementsBuilder qscd(boolean qscd) {
    this.qscd = qscd;
    return this;
  }

  public QcStatementsBuilder qcTypes(List<ASN1ObjectIdentifier> qcTypes) {
    this.qcTypes = qcTypes;
    return this;
  }

  public QcStatementsBuilder legislationCountries(List<String> legislationCountries) {
    this.legislationCountries = legislationCountries;
    return this;
  }

  public QcStatementsBuilder relianceLimit(MonetaryValue relianceLimit) {
    this.relianceLimit = relianceLimit;
    return this;
  }

  public QcStatementsBuilder retentionPeriod(Integer retentionPeriod) {
    this.retentionPeriod = retentionPeriod;
    return this;
  }

  public QcStatementsBuilder pdsLocations(List<PDSLocation> pdsLocations) {
    this.pdsLocations = pdsLocations;
    return this;
  }

  /**
   * Builds a QCStatements extension object
   *
   * @return {@link QCStatements}
   */
  public QCStatements build() {

    QCStatements qcStatements = new QCStatements();

    if (versionAndSemantics != null) {
      switch (versionAndSemantics.getVersion()) {
      case V1:
        qcStatements.setPkixSyntaxV1(true);
        break;
      case V2:
        qcStatements.setPkixSyntaxV2(true);
        break;
      }
      qcStatements.setSemanticsInfo(versionAndSemantics.getSemanticsInformation());
    }

    if (qualifiedCertificate)
      qcStatements.setQcCompliance(true);
    if (qscd)
      qcStatements.setQcSscd(true);

    if (qcTypes != null && !qcTypes.isEmpty()) {
      qcStatements.setQcType(true);
      qcStatements.setQcTypeIdList(qcTypes);
    }

    if (legislationCountries != null && !legislationCountries.isEmpty()) {
      qcStatements.setQcCClegislation(true);
      qcStatements.setLegislationCountryList(legislationCountries);
    }

    if (relianceLimit != null) {
      qcStatements.setLimitValue(true);
      qcStatements.setMonetaryValue(relianceLimit);
    }

    if (retentionPeriod != null) {
      qcStatements.setRetentionPeriod(true);
      qcStatements.setRetentionPeriodVal(new BigInteger(String.valueOf(retentionPeriod)));
    }

    if (pdsLocations != null && !pdsLocations.isEmpty()) {
      qcStatements.setPdsStatement(true);
      qcStatements.setLocationList(pdsLocations);
    }
    return qcStatements;
  }

}
