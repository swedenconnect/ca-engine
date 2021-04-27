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

package se.swedenconnect.ca.service.base.utils;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import se.swedenconnect.ca.service.base.configuration.keys.BasicX509Utils;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class GeneralCAUtils {

  public static X509CertificateHolder getOcspCert(File configFolder, String instance) throws IOException, CertificateEncodingException {
    File certDir = new File(configFolder , "instances/"+ instance+"/certs");
    if (certDir.exists()){
      Optional<File> ocspCertFile = Arrays.stream(certDir.listFiles((dir, name) -> name.endsWith("ocsp.crt"))).findFirst();
      if (ocspCertFile.isPresent()) {
        X509CertificateHolder ocspIssuerCert = new JcaX509CertificateHolder(
          Objects.requireNonNull(
            BasicX509Utils.getCertOrNull(
              FileUtils.readFileToByteArray(ocspCertFile.get()))));
        return ocspIssuerCert;
      }
    }
    return null;
  }

  public static boolean isOCSPCert(X509CertificateHolder cert) {
    try {
      return ExtendedKeyUsage.fromExtensions(cert.getExtensions()).hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning);
    }
    catch (Exception ignored) {
    }
    return false;
  }

}
