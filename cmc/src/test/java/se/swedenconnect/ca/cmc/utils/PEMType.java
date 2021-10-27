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

package se.swedenconnect.ca.cmc.utils;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
@AllArgsConstructor
public enum PEMType {
  certRequest("CERTIFICATE REQUEST"),
  newCertRequest("NEW CERTIFICATE REQUEST"),
  cert("CERTIFICATE"),
  trustedCert("TRUSTED CERTIFICATE"),
  x509Cert("X509 CERTIFICATE"),
  crl("X509 CRL"),
  pkcs7("PKCS7"),
  cms("CMS"),
  attributeCert("ATTRIBUTE CERTIFICATE"),
  ecParams("EC PARAMETERS"),
  publicKey("PUBLIC KEY"),
  rsaPublicKey("RSA PUBLIC KEY"),
  rsaPrivateKey("RSA PRIVATE KEY"),
  dsaPrivateKey("DSA PRIVATE KEY"),
  ecPrivateKey("EC PRIVATE KEY"),
  encryptedPrivateKey("ENCRYPTED PRIVATE KEY"),
  privateKey("PRIVATE KEY");

  private String header;

}
