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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.extension.AbstractExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.EntityType;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModelUtils;
import se.idsec.x509cert.extensions.SubjectInformationAccess;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Model for subject and authority information access extensions.
 * The subject boolean flag determines the type of extension created.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class InformationAccessModel extends AbstractExtensionModel {

  public static final ASN1ObjectIdentifier CA_REPOSITORY = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.5");
  public static final ASN1ObjectIdentifier TIMESTAMPING = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.3");

  /** Set to true if the extension is a SubjectInfoAccess Extension and false for an AuthorityInfoAccess Extension */
  private final EntityType entityType;

  /** Set to true to force this extension to be critical. RFC 5280 recommends that this extension is not critical */
  @Setter
  private boolean critical = false;

  /** List of */
  private List<AccessDescriptionParams> accessDescriptionList;

  public InformationAccessModel(EntityType entityType, AccessDescriptionParams... accessDescriptionParams) {
    this.entityType = entityType;
    this.accessDescriptionList = Arrays.asList(accessDescriptionParams);
  }

  @Override protected ExtensionMetadata getExtensionMetadata() {
    return new ExtensionMetadata(
      entityType.equals(EntityType.subject) ? Extension.subjectInfoAccess : Extension.authorityInfoAccess,
      entityType.equals(EntityType.subject) ? "SubjectInfoAccess" : "AuthorityInfoAccess",
      critical
    );
  }

  @Override protected ASN1Object getExtensionObject() throws CertificateIssuanceException {
    if (accessDescriptionList == null || accessDescriptionList.isEmpty()) {
      throw new CertificateIssuanceException("The Access Info extension MUST contain at least one access description");
    }
    List<AccessDescription> distributionPointList = new ArrayList<>();

    for (AccessDescriptionParams adp : accessDescriptionList) {

      String accessPointURI = adp.accessLocationURI;
      ASN1ObjectIdentifier accessMethod = adp.getAccessMethod();
      ExtensionModelUtils.testUriString(accessPointURI);
      distributionPointList.add(new AccessDescription(accessMethod, new GeneralName(6, accessPointURI)));
    }

    AccessDescription[] accessDescriptions = distributionPointList.toArray(new AccessDescription[distributionPointList.size()]);

    ASN1Object infoAccessExt = entityType.equals(EntityType.subject)
      ? new SubjectInformationAccess(accessDescriptions)
      : new AuthorityInformationAccess(accessDescriptions);
    return infoAccessExt;
  }

  @Data
  @AllArgsConstructor
  @Builder
  public static class AccessDescriptionParams {

    private ASN1ObjectIdentifier accessMethod;
    private String accessLocationURI;

  }
}
