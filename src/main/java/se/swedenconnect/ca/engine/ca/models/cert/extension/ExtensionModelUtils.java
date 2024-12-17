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
package se.swedenconnect.ca.engine.ca.models.cert.extension;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;

/**
 * Utility class for extension model processing.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class ExtensionModelUtils {

  /**
   * Tests the URI string.
   *
   * @param uriStr URI string
   * @throws CertificateIssuanceException if the URI is illegal or is not supported
   */
  public static void testUriString(final String uriStr) throws CertificateIssuanceException {
    try {
      final URI uri = new URI(uriStr);
      final String protocol = uri.getScheme();
      switch (protocol) {
      case "http":
      case "https":
      case "ldap":
      case "ldaps":
        break;
      default:
        throw new IOException("Illegal URI protocol: " + protocol + " in URI: " + uriStr);
      }
    }
    catch (final URISyntaxException e) {
      log.debug("Illegal URI {}", uriStr);
      throw new CertificateIssuanceException("Illegal URI", e);
    }
    catch (final IOException e) {
      log.debug("Unsupported URI protocol {}", uriStr);
      throw new CertificateIssuanceException("Illegal URI", e);
    }
  }

}
