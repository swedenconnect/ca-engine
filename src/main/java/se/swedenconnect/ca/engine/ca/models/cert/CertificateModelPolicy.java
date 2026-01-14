/*
 * Copyright 2026 Agency for Digital Government (DIGG)
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

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;

public interface CertificateModelPolicy {

  String CRL_DP_POLICY = "crl_dp";
  String OCSP_URL_POLICY = "ocsp_url";

  void applyPolicy(CertificateModel certificateModel) throws CertificateIssuanceException;

}
