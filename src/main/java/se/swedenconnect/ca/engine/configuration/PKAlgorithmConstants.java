/*
 * Copyright 2021-2023 Agency for Digital Government (DIGG)
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
package se.swedenconnect.ca.engine.configuration;

/**
 * Constants for algorithm properties.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PKAlgorithmConstants {
  /** RSA */
  public static final String KEY_ALGO_RSA = "RSA";

  /** DSA */
  public static final String KEY_ALGO_DSA = "DSA";

  /** Elliptic Curve */
  public static final String KEY_ALGO_EC = "EC";

  /** AES crypto */
  public static final String KEY_ALGO_AES = "AES";

  /** DES Crypto */
  public static final String KEY_ALGO_DES = "DES";

  /** DESede */
  public static final String KEY_ALGO_DESEDE = "DESede";

  /** Raw encryption/decryption */
  public static final String KEY_FORMAT_RAW = "RAW";

  /** Electronic codebook mode */
  public static final String CIPHER_MODE_ECB = "ECB";

  /** Cipher Block chaining mode */
  public static final String CIPHER_MODE_CBC = "CBC";

  /** Galois Counter Mode */
  public static final String CIPHER_MODE_GCM = "GCM";

  /** No Padding */
  public static final String CIPHER_PADDING_NONE = "NoPadding";

  /** ISO 10126 padding */
  public static final String CIPHER_PADDING_ISO10126 = "ISO10126Padding";

  /** PKCS#1 1.5 padding */
  public static final String CIPHER_PADDING_PKCS1 = "PKCS1Padding";

  /** OAEP padding */
  public static final String CIPHER_PADDING_OAEP = "OAEPPadding";

  /** DESede wrap */
  public static final String KEYWRAP_ALGO_DESEDE = "DESedeWrap";

  /** AES wrap */
  public static final String KEYWRAP_ALGO_AES = "AESWrap";
}
