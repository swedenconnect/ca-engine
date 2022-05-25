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

package se.swedenconnect.ca.engine.ca.models.cert;

/**
 * Interface for name model for subject and issuer names
 * @param <T> type of name data carried in this name model
 */
public interface CertNameModel<T extends Object> {

  /**
   * Get the type of certificate name model
   *
   * @return {@link CertNameModel}
   */
  CertNameModelType getType();

  /**
   * Get the underlying name data
   *
   * @return {@link CertNameModel}
   */
  T getNameData();

  /**
   * Enumeration of certificate name model types
   */
  enum CertNameModelType {
    /** Explicit information about every attribute and their encoding **/
    explicit,
    /** Model is provided by an encoded ASN.1 object holding the certificate name information */
    encoded;
  }

}
