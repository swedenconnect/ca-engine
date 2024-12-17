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

package se.swedenconnect.ca.engine.utils;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.encoders.Base64;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class TestUtils {

  /**
   * Print Base64 encoded data
   *
   * @param data data to print in base64 form
   * @return formatted output string
   */
  public static String base64Print(byte[] data) {
    return base64Print(data, 80);
  }

  /**
   * Print Base64 encoded data
   *
   * @param data data to print in base64 form
   * @return formatted output string
   */
  public static String base64Print(String data) {
    return base64Print(data, 80);
  }

  /**
   * Print Base64 encoded data
   *
   * @param data data to print in base64 form
   * @param width requested width of printed data (excluding indentation)
   * @return formatted output string
   */
  public static String base64Print(String data, int width) {
    return base64Print(Base64.decode(data), width);
  }

  /**
   * Print Base64 encoded data
   *
   * @param data data to print in base64 form
   * @param width requested width of printed data (excluding indentation)
   * @return formatted output string
   */
  public static String base64Print(byte[] data, int width) {
    // Create a String with linebreaks
    String b64String = Base64.toBase64String(data).replaceAll("(.{" + width + "})", "$1\n");
    // Ident string with 6 spaces
    return b64String.replaceAll("(?m)^", "      ");
  }


}
