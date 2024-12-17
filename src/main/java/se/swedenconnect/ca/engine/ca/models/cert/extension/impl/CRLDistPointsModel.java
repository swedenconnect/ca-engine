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
package se.swedenconnect.ca.engine.ca.models.cert.extension.impl;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import lombok.Setter;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.extension.AbstractExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModelUtils;

/**
 * Model for CRLDistribution point extensions
 *
 * <pre>
 * DistributionPoint ::= SEQUENCE {
 * distributionPoint       [0]     DistributionPointName OPTIONAL,
 * reasons                 [1]     ReasonFlags OPTIONAL,
 * cRLIssuer               [2]     GeneralNames OPTIONAL }
 * </pre>
 * <p>
 * cRLIssuer MUST NOT be present if the CA is the CRLIssuer reasons are only applicable if the CRL only covers some
 * reasons. This is discouraged in RFC 5280. This model only allows inclusion of distribution points.
 * </p>
 * <p>
 * All listed URL:s must be either ldap or http(s) URL:s.
 * </p>
 *
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CRLDistPointsModel extends AbstractExtensionModel {

  /** Set to true to force this extension to be critical. RFC 5280 recommends that this extension is not critical */
  @Setter
  private boolean critical = false;

  /** A list of http(s) or ldap URLs pointing to published CRL for this certificate */
  List<String> distributionPointUrlList;

  /**
   * Constructor for the CRL Distribution points extension model
   *
   * @param distributionPointUrlList list of distribution point URLs
   */
  public CRLDistPointsModel(final List<String> distributionPointUrlList) {
    this.distributionPointUrlList = distributionPointUrlList;
  }

  @Override
  protected ExtensionMetadata getExtensionMetadata() {
    return new ExtensionMetadata(Extension.cRLDistributionPoints, "CRL distribution points", this.critical);
  }

  @Override
  protected ASN1Object getExtensionObject() throws CertificateIssuanceException {
    if (this.distributionPointUrlList == null || this.distributionPointUrlList.isEmpty()) {
      throw new CertificateIssuanceException("The CRL Distribution point extension MUST contain at least one URL");
    }
    final List<DistributionPoint> distributionPointList = new ArrayList<>();

    for (final String dpUrl : this.distributionPointUrlList) {

      // Check URI
      ExtensionModelUtils.testUriString(dpUrl);
      // Store CRL DP
      distributionPointList.add(
          new DistributionPoint(
              new DistributionPointName(
                  new GeneralNames(
                      new GeneralName(6, dpUrl))),
              null, null));
    }

    final CRLDistPoint crlDp =
        new CRLDistPoint(distributionPointList.toArray(new DistributionPoint[distributionPointList.size()]));
    return crlDp;
  }

}
