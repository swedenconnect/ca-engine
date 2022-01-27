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

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionIdAndCrit;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class InheritExtensionModel implements ExtensionModel {

  private X509CertificateHolder certificateHolder;
  private List<ExtensionIdAndCrit> extensionIdList;

  public InheritExtensionModel(X509CertificateHolder certificateHolder, ExtensionIdAndCrit... extensionId) {
    this.certificateHolder = certificateHolder;
    this.extensionIdList = Arrays.asList(extensionId);
  }

  @Override public void addExtensions(JcaX509v3CertificateBuilder certificateBuilder) throws CertificateIssuanceException {
    try {
      for (ExtensionIdAndCrit extensionIdAndCrit : extensionIdList) {
        certificateBuilder.copyAndAddExtension(extensionIdAndCrit.getOid(), extensionIdAndCrit.isCritical(), certificateHolder);
        log.debug("Added extension copy from cert {}", extensionIdAndCrit.getOid());
      }
    }
    catch (Exception ex) {
      throw new CertificateIssuanceException("Error while attempting to copy extension from cert", ex);
    }
  }

  @Override public List<Extension> getExtensions() throws CertificateIssuanceException {
    try {
      List<Extension> extensionList = new ArrayList<>();
      for (ExtensionIdAndCrit extensionIdAndCrit : extensionIdList) {
        Extension extractExtension = certificateHolder.getExtension(extensionIdAndCrit.getOid());
        Extension newExtension = new Extension(extensionIdAndCrit.getOid(), extensionIdAndCrit.isCritical(), extractExtension.getExtnValue());
        extensionList.add(newExtension);
        log.debug("Added extension copy from cert {}", extensionIdAndCrit.getOid());
      }
      return extensionList;
    }
    catch (Exception ex) {
      throw new CertificateIssuanceException("Error while attempting to copy extension from cert", ex);
    }
  }
}
