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

package se.swedenconnect.ca.engine.utils;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Utility functions in support of the CA library
 */
@Slf4j
public class CAUtils {

  /**
   * Private constructor preventing instantiation
   */
  private CAUtils() {
  }

  /**
   * Internal function to convert {@link X509CertificateHolder} to {@link X509Certificate}
   *
   * @param cert certificate to convert
   * @return {@link X509Certificate}
   * @throws IOException          input data error
   * @throws CertificateException certificate encoding errors
   */
  public static X509Certificate getCert(X509CertificateHolder cert) throws IOException, CertificateException {
    try (InputStream inStream = new ByteArrayInputStream(cert.getEncoded())) {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(inStream);
    }
  }
}
