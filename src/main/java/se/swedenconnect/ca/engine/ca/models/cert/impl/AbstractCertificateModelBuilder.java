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

package se.swedenconnect.ca.engine.ca.models.cert.impl;

import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x509.*;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.EntityType;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CRLDistPointsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.InformationAccessModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.SubjDirectoryAttributesModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.*;
import se.idsec.x509cert.extensions.QCStatements;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.*;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.SAMLAuthContext;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Abstract implementation of the certificate model builder interface
 *
 * @param <T> The class of the implementation of this abstract class
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public abstract class AbstractCertificateModelBuilder<T extends CertificateModelBuilder> implements CertificateModelBuilder {

  /** Certificate subject name */
  protected CertNameModel subject;
  /** Subject alternative name indexed by the subject alt name type identifier */
  protected Map<Integer, String> subjectAltNames;
  /** Basic constraints model */
  protected BasicConstraintsModel basicConstraints;
  /** true if an Authority key identifier is to be included */
  protected boolean includeAki;
  /** true if an Subject key identifier is to be included */
  protected boolean includeSki;
  /** key usage settings according to X.509 see {@link KeyUsage} */
  protected KeyUsageModel keyUsage;
  /** Extended key usage model */
  protected ExtendedKeyUsageModel extendedKeyUsage;
  /** List of CRL distribution point URL:s */
  protected List<String> crlDistributionPoints;
  /** URL for an OCSP service authorized for the issued certificate */
  protected String ocspServiceUrl;
  /** URL where the issuer certificate is published */
  protected String issuerCertUrl;
  /** URL where certificates issued by the CA of this certificate are located */
  protected String caRepositoryUrl;
  /** URL where the timestamp service represented by this certificate is located */
  protected String timeStampAuthorityUrl;
  /** Certificate policy model */
  protected CertificatePolicyModel certificatePolicy;
  /** SAML authentication context model */
  protected SAMLAuthContext authenticationContext;
  /** QC statements */
  protected QCStatements qcStatements;
  /** true to include an OCSP no check extension */
  protected boolean ocspNocheck;
  /** subject attributes extension model */
  protected SubjDirectoryAttributesModel subjectDirectoryAttributes;

  public T subject(CertNameModel subject) {
    this.subject = subject;
    return (T) this;
  }

  public T subjectAltNames(Map<Integer, String> subjectAltNames) {
    this.subjectAltNames = subjectAltNames;
    return (T) this;
  }

  public T basicConstraints(BasicConstraintsModel basicConstraints) {
    this.basicConstraints = basicConstraints;
    return (T) this;
  }

  public T includeAki(boolean includeAki) {
    this.includeAki = includeAki;
    return (T) this;
  }

  public T includeSki(boolean includeSki) {
    this.includeSki = includeSki;
    return (T) this;
  }

  public T keyUsage(KeyUsageModel keyUsage) {
    this.keyUsage = keyUsage;
    return (T) this;
  }

  public T extendedKeyUsage(ExtendedKeyUsageModel extendedKeyUsage) {
    this.extendedKeyUsage = extendedKeyUsage;
    return (T) this;
  }

  public T crlDistributionPoints(List<String> crlDistributionPoints) {
    this.crlDistributionPoints = crlDistributionPoints;
    return (T) this;
  }

  public T ocspServiceUrl(String ocspServiceUrl) {
    this.ocspServiceUrl = ocspServiceUrl;
    return (T) this;
  }

  public T issuerCertUrl(String issuerCertUrl) {
    this.issuerCertUrl = issuerCertUrl;
    return (T) this;
  }

  public T caRepositoryUrl(String caRepositoryUrl) {
    this.caRepositoryUrl = caRepositoryUrl;
    return (T) this;
  }

  public T timeStampAuthorityUrl(String timeStampAuthorityUrl) {
    this.timeStampAuthorityUrl = timeStampAuthorityUrl;
    return (T) this;
  }

  public T certificatePolicy(CertificatePolicyModel certificatePolicy) {
    this.certificatePolicy = certificatePolicy;
    return (T) this;
  }

  public T authenticationContext(SAMLAuthContext authenticationContext) {
    this.authenticationContext = authenticationContext;
    return (T) this;
  }

  public T qcStatements(QCStatements qcStatements) {
    this.qcStatements = qcStatements;
    return (T) this;
  }

  public T ocspNocheck(boolean ocspNocheck) {
    this.ocspNocheck = ocspNocheck;
    return (T) this;
  }

  public T subjectDirectoryAttributes(SubjDirectoryAttributesModel subjectDirectoryAttributes) {
    this.subjectDirectoryAttributes = subjectDirectoryAttributes;
    return (T) this;
  }

  @Override public abstract CertificateModel build() throws CertificateIssuanceException;

  protected abstract void getKeyIdentifierExtensionsModels(List<ExtensionModel> extm) throws IOException;

  /**
   * Get the default basic extension models for all model data extensions except for AKI and SKI extensions
   *
   * @return extension model list
   * @throws IOException errors creating extension model list
   */
  protected List<ExtensionModel> getExtensionModels() throws IOException {
    List<ExtensionModel> extm = new ArrayList<>();

    // Basic constraints
    if (basicConstraints != null) {
      extm.add(basicConstraints);
    }

    // Get custom implemented key identifier extensioins
    getKeyIdentifierExtensionsModels(extm);

    // Key usage
    if (keyUsage != null)
      extm.add(keyUsage);

    // Extended key usage
    if (extendedKeyUsage != null)
      extm.add(extendedKeyUsage);

    // CRL Distribution points
    if (crlDistributionPoints != null && !crlDistributionPoints.isEmpty()) {
      extm.add(new CRLDistPointsModel(crlDistributionPoints));
    }

    //Authority info access
    if (StringUtils.isNotBlank(issuerCertUrl) || StringUtils.isNotBlank(ocspServiceUrl)) {
      List<InformationAccessModel.AccessDescriptionParams> accessDescParamList = new ArrayList<>();
      if (StringUtils.isNotBlank(issuerCertUrl)) {
        accessDescParamList.add(InformationAccessModel.AccessDescriptionParams.builder()
          .accessMethod(AccessDescription.id_ad_caIssuers)
          .accessLocationURI(issuerCertUrl)
          .build());
      }
      if (StringUtils.isNotBlank(ocspServiceUrl)) {
        accessDescParamList.add(InformationAccessModel.AccessDescriptionParams.builder()
          .accessMethod(AccessDescription.id_ad_ocsp)
          .accessLocationURI(ocspServiceUrl)
          .build());
      }
      extm.add(new InformationAccessModel(EntityType.issuer, accessDescParamList.toArray(
        new InformationAccessModel.AccessDescriptionParams[accessDescParamList.size()])));
    }

    //Subject info access
    if (StringUtils.isNotBlank(caRepositoryUrl) || StringUtils.isNotBlank(timeStampAuthorityUrl)) {
      List<InformationAccessModel.AccessDescriptionParams> accessDescParamList = new ArrayList<>();
      if (StringUtils.isNotBlank(caRepositoryUrl)) {
        accessDescParamList.add(InformationAccessModel.AccessDescriptionParams.builder()
          .accessMethod(InformationAccessModel.CA_REPOSITORY)
          .accessLocationURI(caRepositoryUrl)
          .build());
      }
      if (StringUtils.isNotBlank(timeStampAuthorityUrl)) {
        accessDescParamList.add(InformationAccessModel.AccessDescriptionParams.builder()
          .accessMethod(InformationAccessModel.TIMESTAMPING)
          .accessLocationURI(timeStampAuthorityUrl)
          .build());
      }
      extm.add(new InformationAccessModel(EntityType.subject, accessDescParamList.stream().toArray(
        InformationAccessModel.AccessDescriptionParams[]::new)));
    }

    // Certificate policies
    if (certificatePolicy != null)
      extm.add(certificatePolicy);

    // Authn context
    if (authenticationContext != null)
      extm.add(new AuthnContextModel(authenticationContext));

    //QC Statements
    if (qcStatements != null)
      extm.add(new QCStatementsExtensionModel(qcStatements));

    // Subject alternative names
    if (subjectAltNames != null && !subjectAltNames.isEmpty()) {
      GeneralName[] generalNames = subjectAltNames.keySet().stream()
        .map(integer -> new GeneralName(integer, subjectAltNames.get(integer)))
        .toArray(GeneralName[]::new);
      extm.add(new AlternativeNameModel(EntityType.subject, generalNames));

    }

    //Subject directory attributes
    if (subjectDirectoryAttributes != null)
      extm.add(subjectDirectoryAttributes);

    // OCSP Nocheck
    if (ocspNocheck) {
      extm.add(new OCSPNoCheckModel());
    }
    return extm;
  }

}
