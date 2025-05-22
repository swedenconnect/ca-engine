/*
 * Copyright 2021-2025 Sweden Connect
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
package se.swedenconnect.ca.engine.data;

import java.security.KeyPair;

import lombok.AllArgsConstructor;
import lombok.Getter;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;

/**
 * Enumeration of configuration data for test CA providers*
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@AllArgsConstructor
@Getter
public enum TestCa {
  RSA_CA(
    "rsa-ca",
    "RSA Root CA",
    TestData.rsa3072kp,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA512,
    "RSA Test CA",
    TestData.rsa2048kp01,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA256,
    "RSA OCSP responder",
    TestData.rsa2048kp02,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA256),

  RSA_PSS_CA("rsa-pss-ca",
    "RSA PSS Root CA",
    TestData.rsa3072kp,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1,
    "RSA PSS Test CA",
    TestData.rsa2048kp01,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1,
    "RSA PSS OCSP responder",
    TestData.rsa2048kp02,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA256),
  ECDSA_CA("ecdsa-ca",
    "ECDSA Root CA",
    TestData.ec521kp,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA512,
    "ECDSA Test CA",
    TestData.ec256kp01,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA256,
    "ECDSA OCSP responder",
    TestData.ec256kp02,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA256),
  RSA_EC_CA("rsa-ec-ca",
    "RSA EC Root CA",
    TestData.rsa3072kp,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA512,
    "RSA EC Test CA",
    TestData.ec256kp01,
    CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA256,
    "RSA EC OCSP responder",
    null, null);

  String id;
  String rootName;
  KeyPair rootKeyPair;
  String rootAlgo;
  String caName;
  KeyPair caKeyPair;
  String caAlgo;
  String ocspName;
  KeyPair ocspKeyPair;
  String ocspAlgo;

}
