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

package se.swedenconnect.ca.engine.ca.models.cert.extension.impl;

import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.extension.AbstractExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModelUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Provides data for creating a certificate policies extension
 * This model does only support explicit text option of qualifiers and CPS URI
 * in accordance with RFC 5280 recommendations
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CertificatePolicyModel extends AbstractExtensionModel {

  public static final ASN1ObjectIdentifier ANY_POLICY = new ASN1ObjectIdentifier("2.5.29.32.0");

  /** indicates if this extension should be critical */
  @Setter private boolean critical = false;

  /** indicates if the 200 character limit of explicit text is enforced */
  @Setter private boolean enforce200CharLimit = true;

  /** Policy oid and qualifier parameters */
  private List<PolicyInfoParams> policyInfoParamsList;

  /**
   * Constuctor
   *
   * @param anyPolicy set to true to include an any policy identifier (OID 2.5.29.32.0)
   */
  public CertificatePolicyModel(boolean anyPolicy) {
    policyInfoParamsList = anyPolicy
      ? Arrays.asList(PolicyInfoParams.builder().policy(ANY_POLICY).build())
      : new ArrayList<>();
  }

  /**
   * Constructor
   *
   * @param critical          criticality of the extension
   * @param certificatePolicy one or more certificate policy object identifiers
   */
  public CertificatePolicyModel(boolean critical, ASN1ObjectIdentifier... certificatePolicy) {
    this.critical = critical;
    policyInfoParamsList = Arrays.asList(certificatePolicy).stream()
      .map(asn1ObjectIdentifier -> PolicyInfoParams.builder().policy(asn1ObjectIdentifier).build())
      .collect(Collectors.toList());
  }

  /**
   * Constructor
   *
   * @param critical             criticality of the extension
   * @param policyInfoParamsList list of policy information model objects holding information about a policy and its qualifiers
   */
  public CertificatePolicyModel(
    boolean critical, List<PolicyInfoParams> policyInfoParamsList) {
    this.critical = critical;
    this.policyInfoParamsList = policyInfoParamsList;
  }

  @Override protected ASN1Object getExtensionObject() throws CertificateIssuanceException {
    if (policyInfoParamsList == null || policyInfoParamsList.isEmpty()) {
      throw new CertificateIssuanceException("The Certificate Policies extension MUST contain at least one policy");
    }
    List<PolicyInformation> policyInformationList = new ArrayList<>();

    for (PolicyInfoParams pip : policyInfoParamsList) {

      if (pip.getPolicy() == null) {
        throw new CertificateIssuanceException("Policy information contains a null policy");
      }
      ASN1Sequence qualifiers = getPolicyQualifiers(pip);
      policyInformationList.add(new PolicyInformation(pip.getPolicy(), qualifiers));
    }

    CertificatePolicies certificatePolicies = new CertificatePolicies(
      policyInformationList.toArray(new PolicyInformation[policyInformationList.size()])
    );

    return certificatePolicies;
  }

  @Override protected ExtensionMetadata getExtensionMetadata() {
    return new ExtensionMetadata(Extension.certificatePolicies, "Certificate policies", critical);
  }

  private ASN1Sequence getPolicyQualifiers(PolicyInfoParams pip) throws CertificateIssuanceException {
    String cpsUri = pip.getCpsUri();
    String displayText = pip.getDisplayText();
    if (StringUtils.isBlank(cpsUri) && StringUtils.isBlank(displayText)) {
      // No qualifiers. Return null qualifiers
      return null;
    }
    // Set the present qualifiers
    ASN1EncodableVector policyQualifierInfoSequence = new ASN1EncodableVector();

    if (StringUtils.isNotBlank(cpsUri)) {
      ExtensionModelUtils.testUriString(cpsUri);
      policyQualifierInfoSequence.add(new PolicyQualifierInfo(cpsUri));
    }
    displayText = displayText.trim();
    if (StringUtils.isNotBlank(displayText)) {
      if (enforce200CharLimit && displayText.length() > 200) {
        throw new CertificateIssuanceException("Qualifier display text exceeds maximum length of 200 characters");
      }
      ASN1EncodableVector userNoticeSequence = new ASN1EncodableVector();
      userNoticeSequence.add(new DERUTF8String(displayText));
      policyQualifierInfoSequence.add(new PolicyQualifierInfo(PolicyQualifierId.id_qt_unotice, new DERSequence(userNoticeSequence)));
    }
    return new DERSequence(policyQualifierInfoSequence);
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  @Builder
  public static class PolicyInfoParams {
    ASN1ObjectIdentifier policy;
    String cpsUri;
    String displayText;
  }

}
