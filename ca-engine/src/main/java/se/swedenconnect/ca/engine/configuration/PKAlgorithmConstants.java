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

package se.swedenconnect.ca.engine.configuration;

/**
 * Constants for algorithm properties
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PKAlgorithmConstants {
  public static final String KEY_ALGO_RSA = "RSA";
  public static final String KEY_ALGO_DSA = "DSA";
  public static final String KEY_ALGO_EC = "EC";
  public static final String KEY_ALGO_AES = "AES";
  public static final String KEY_ALGO_DES = "DES";
  public static final String KEY_ALGO_DESEDE = "DESede";
  public static final String KEY_FORMAT_RAW = "RAW";
  public static final String CIPHER_MODE_ECB = "ECB";
  public static final String CIPHER_MODE_CBC = "CBC";
  public static final String CIPHER_MODE_GCM = "GCM";
  public static final String CIPHER_PADDING_NONE = "NoPadding";
  public static final String CIPHER_PADDING_ISO10126 = "ISO10126Padding";
  public static final String CIPHER_PADDING_PKCS1 = "PKCS1Padding";
  public static final String CIPHER_PADDING_OAEP = "OAEPPadding";
  public static final String KEYWRAP_ALGO_DESEDE = "DESedeWrap";
  public static final String KEYWRAP_ALGO_AES = "AESWrap";
}
