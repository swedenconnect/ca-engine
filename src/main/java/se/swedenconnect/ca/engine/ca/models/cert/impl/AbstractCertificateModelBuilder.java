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
import se.swedenconnect.cert.extensions.QCStatements;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.*;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.SAMLAuthContext;

import java.io.IOException;
import java.util.*;

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
  protected CertNameModel<?> subject;
  /** Subject alternative name indexed by the subject alt name type identifier */
  protected Map<Integer, List<String>> subjectAltNames;
  /** Criticality of subjectAltName extension */
  protected boolean subjectAltNameCritical = false;
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

  /**
   * Set certificate subject name
   *
   * @param subject certificate subject name
   * @return this builder
   */
  public T subject(CertNameModel<?> subject) {
    this.subject = subject;
    return (T) this;
  }

  /**
   * Set subject alt names data
   *
   * @param simpleSubjectAltNames simple data input with single value per type
   * @return this builder
   */
  public T subjectAltNames(Map<Integer, String> simpleSubjectAltNames) {
    Map<Integer, List<String>> extendedSubjectAltNameMap = null;
    if (simpleSubjectAltNames != null){
      extendedSubjectAltNameMap = new HashMap<>();
      for (Integer generalNameIndex : simpleSubjectAltNames.keySet()){
        extendedSubjectAltNameMap.put(generalNameIndex, Collections.singletonList(simpleSubjectAltNames.get(generalNameIndex)));
      }
    }
    this.subjectAltNameCritical = false;
    this.subjectAltNames = extendedSubjectAltNameMap;
    return (T) this;
  }

  /**
   * Set subject alt names data
   *
   * @param critical criticality
   * @param subjectAltNames subject alt name data
   * @return this builder
   */
  public T subjectAltNames(boolean critical, Map<Integer, List<String>> subjectAltNames) {
    this.subjectAltNames = subjectAltNames;
    this.subjectAltNameCritical = critical;
    return (T) this;
  }

  /**
   * Set basic constraints.
   *
   * @param basicConstraints basic constraints data
   * @return this builder
   */
  public T basicConstraints(BasicConstraintsModel basicConstraints) {
    this.basicConstraints = basicConstraints;
    return (T) this;
  }

  /**
   * Defines if this builder should include an AKI (Authority Key Identifier)
   *
   * @param includeAki true to include AKI
   * @return this builder
   */
  public T includeAki(boolean includeAki) {
    this.includeAki = includeAki;
    return (T) this;
  }

  /**
   * Defines if this builder should include an SKI (Subject Key Identifier)
   *
   * @param includeSki true to include SKI
   * @return this builder
   */
  public T includeSki(boolean includeSki) {
    this.includeSki = includeSki;
    return (T) this;
  }

  /**
   * Set key usage
   *
   * @param keyUsage key usage
   * @return this builder
   */
  public T keyUsage(KeyUsageModel keyUsage) {
    this.keyUsage = keyUsage;
    return (T) this;
  }

  /**
   * Set extended key usage
   *
   * @param extendedKeyUsage extended key usage
   * @return this builder
   */
  public T extendedKeyUsage(ExtendedKeyUsageModel extendedKeyUsage) {
    this.extendedKeyUsage = extendedKeyUsage;
    return (T) this;
  }

  /**
   * Set CRL distribution points
   *
   * @param crlDistributionPoints CRL distribution points
   * @return this builder
   */
  public T crlDistributionPoints(List<String> crlDistributionPoints) {
    this.crlDistributionPoints = crlDistributionPoints;
    return (T) this;
  }

  /**
   * Set OCSP service URL
   *
   * @param ocspServiceUrl OCSP service URL
   * @return this builder
   */
  public T ocspServiceUrl(String ocspServiceUrl) {
    this.ocspServiceUrl = ocspServiceUrl;
    return (T) this;
  }

  /**
   * Set issuer certificate URL for the AIA extension
   *
   * @param issuerCertUrl issuer certificate URL
   * @return this builder
   */
  public T issuerCertUrl(String issuerCertUrl) {
    this.issuerCertUrl = issuerCertUrl;
    return (T) this;
  }

  /**
   * Set CA Repository URL
   *
   * @param caRepositoryUrl CA repository URL
   * @return this builder
   */
  public T caRepositoryUrl(String caRepositoryUrl) {
    this.caRepositoryUrl = caRepositoryUrl;
    return (T) this;
  }

  /**
   * Set timestamp authority URL
   *
   * @param timeStampAuthorityUrl timestamp authority URL
   * @return this builder
   */
  public T timeStampAuthorityUrl(String timeStampAuthorityUrl) {
    this.timeStampAuthorityUrl = timeStampAuthorityUrl;
    return (T) this;
  }

  /**
   * Set certificate policy data
   *
   * @param certificatePolicy certificate policy data
   * @return this builder
   */
  public T certificatePolicy(CertificatePolicyModel certificatePolicy) {
    this.certificatePolicy = certificatePolicy;
    return (T) this;
  }

  /**
   * Set authentication context (RFC 7773)
   *
   * @param authenticationContext authentication context
   * @return this builder
   */
  public T authenticationContext(SAMLAuthContext authenticationContext) {
    this.authenticationContext = authenticationContext;
    return (T) this;
  }

  /**
   * Set QC statements
   *
   * @param qcStatements QC statements
   * @return this builder
   */
  public T qcStatements(QCStatements qcStatements) {
    this.qcStatements = qcStatements;
    return (T) this;
  }

  /**
   * Set OCSP no-check
   *
   * @param ocspNocheck true to include ocsp no-check extension
   * @return this builder
   */
  public T ocspNocheck(boolean ocspNocheck) {
    this.ocspNocheck = ocspNocheck;
    return (T) this;
  }

  /**
   * Set subject directory attributes
   *
   * @param subjectDirectoryAttributes subject directory attributes
   * @return this builder
   */
  public T subjectDirectoryAttributes(SubjDirectoryAttributesModel subjectDirectoryAttributes) {
    this.subjectDirectoryAttributes = subjectDirectoryAttributes;
    return (T) this;
  }

  /** {@inheritDoc} */
  @Override public abstract CertificateModel build() throws CertificateIssuanceException;

  /**
   * Set authority and subject key identifiers
   *
   * @param extm the extension models for this certificate model builder
   * @throws IOException error setting AKI and SKI data
   */
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
        new InformationAccessModel.AccessDescriptionParams[0])));
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
      extm.add(new InformationAccessModel(EntityType.subject,
        accessDescParamList.toArray(InformationAccessModel.AccessDescriptionParams[]::new)));
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
      List<GeneralName> generalNameList = new ArrayList<>();
      for (Integer generalNameIndex : subjectAltNames.keySet()){
        final List<String> valueList = subjectAltNames.get(generalNameIndex);
        for (String value: valueList){
          generalNameList.add(new GeneralName(generalNameIndex, value));
        }
      }
      final AlternativeNameModel alternativeNameModel = new AlternativeNameModel(EntityType.subject,
        generalNameList.toArray(GeneralName[]::new));
      alternativeNameModel.setCritical(subjectAltNameCritical);
      extm.add(alternativeNameModel);
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
