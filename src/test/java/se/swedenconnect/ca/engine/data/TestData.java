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
package se.swedenconnect.ca.engine.data;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.components.CertValidatorComponents;
import se.swedenconnect.ca.engine.components.TestCAProvider;
import se.swedenconnect.ca.engine.components.TestUtils;
import se.swedenconnect.ca.engine.components.TestValidators;

/**
 * Test data used for unit testing
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class TestData {
  public static Map<TestCa, TestCAProvider> testCAs;
  public static Map<TestCa, CertValidatorComponents> certValidators;
  public static KeyPair rsa2048kp01;
  public static KeyPair rsa2048kp02;
  public static KeyPair rsa3072kp;
  public static KeyPair ec256kp01;
  public static KeyPair ec256kp02;
  public static KeyPair ec521kp;

  static {
    testCAs = new HashMap<>();
    certValidators = new HashMap<>();

    try {

      // Generate user key pais
      log.info("Generating rsa 2048 user key");
      rsa2048kp01 = TestUtils.generateRSAKeyPair(2048);
      log.info("Generating rsa 2048 user key");
      rsa2048kp02 = TestUtils.generateRSAKeyPair(2048);
      log.info("Generating rsa 3072 user key");
      rsa3072kp = TestUtils.generateRSAKeyPair(3072);
      log.info("Generating ec P256 user key");
      ec256kp01 = TestUtils.generateECKeyPair(TestUtils.NistCurve.P256);
      log.info("Generating ec P256 user key");
      ec256kp02 = TestUtils.generateECKeyPair(TestUtils.NistCurve.P256);
      log.info("Generating ec P521 user key");
      ec521kp = TestUtils.generateECKeyPair(TestUtils.NistCurve.P521);

/*
      Arrays.stream(TestCa.values())
        .forEach(TestData::addCaAndValidator);
*/

    }
    catch (Exception ignored) {
    }
  }

  public static void addCaAndValidator(TestCa caConfig) {
    try {
      testCAs.put(caConfig, new TestCAProvider(caConfig));
      certValidators.put(caConfig, TestValidators.getCertificateValidator(testCAs.get(caConfig), true));
    }
    catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  public static Map<TestCa, TestCAProvider> getTestCAs() {
    return testCAs;
  }

  public static Map<TestCa, CertValidatorComponents> getCertValidators() {
    return certValidators;
  }
}
