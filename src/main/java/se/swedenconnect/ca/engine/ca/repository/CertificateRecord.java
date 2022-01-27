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

package se.swedenconnect.ca.engine.ca.repository;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CertificateRecord {

  /**
   * Getter for certificate bytes
   * @return certificate bytes
   */
  byte[] getCertificate();

  /**
   * Getter for serial number
   * @return certificate serial number
   */
  java.math.BigInteger getSerialNumber();

  /**
   * Getter for issuer date
   * @return issue date
   */
  java.util.Date getIssueDate();

  /**
   * Getter for expiry date
   * @return expiry date
   */
  java.util.Date getExpiryDate();

  /**
   * Getter for revocation status
   * @return revocation status
   */
  boolean isRevoked();

  /**
   * Getter for revocation reason
   * @return revocation reason
   */
  Integer getReason();

  /**
   * Getter for revocation time
   * @return revocation time
   */
  java.util.Date getRevocationTime();

  /**
   * Setter for certificate bytes
   * @param certificate certificate bytes
   */
  void setCertificate(byte[] certificate);

  /**
   * Setter for certificate serial number
   * @param serialNumber certificate serial number
   */
  void setSerialNumber(java.math.BigInteger serialNumber);

  /**
   * Setter for issue date
   * @param issueDate issue date
   */
  void setIssueDate(java.util.Date issueDate);

  /**
   * Setter for expiry date
   * @param expiryDate expiry date
   */
  void setExpiryDate(java.util.Date expiryDate);

  /**
   * Setter for revocation status
   * @param revoked revocation status
   */
  void setRevoked(boolean revoked);

  /**
   * Setter for revocation reason
   * @param reason revocation reason
   */
  void setReason(Integer reason);

  /**
   * Setter for revocation time
   * @param revocationTime revocatioin time
   */
  void setRevocationTime(java.util.Date revocationTime);
}
