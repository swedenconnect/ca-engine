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
package se.swedenconnect.ca.engine.ca.repository;

import java.math.BigInteger;
import java.util.Date;

/**
 * A certificate record (for storage).
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CertificateRecord {

  /**
   * Getter for certificate bytes.
   *
   * @return certificate bytes
   */
  byte[] getCertificate();

  /**
   * Getter for serial number.
   *
   * @return certificate serial number
   */
  BigInteger getSerialNumber();

  /**
   * Getter for issuer date.
   *
   * @return issue date
   */
  Date getIssueDate();

  /**
   * Getter for expiry date
   *
   * @return expiry date
   */
  Date getExpiryDate();

  /**
   * Getter for revocation status
   *
   * @return revocation status
   */
  boolean isRevoked();

  /**
   * Getter for revocation reason
   *
   * @return revocation reason
   */
  Integer getReason();

  /**
   * Getter for revocation time
   *
   * @return revocation time
   */
  Date getRevocationTime();

  /**
   * Setter for certificate bytes
   *
   * @param certificate certificate bytes
   */
  void setCertificate(final byte[] certificate);

  /**
   * Setter for certificate serial number
   *
   * @param serialNumber certificate serial number
   */
  void setSerialNumber(final BigInteger serialNumber);

  /**
   * Setter for issue date
   *
   * @param issueDate issue date
   */
  void setIssueDate(final Date issueDate);

  /**
   * Setter for expiry date
   *
   * @param expiryDate expiry date
   */
  void setExpiryDate(final Date expiryDate);

  /**
   * Setter for revocation status
   *
   * @param revoked revocation status
   */
  void setRevoked(final boolean revoked);

  /**
   * Setter for revocation reason
   *
   * @param reason revocation reason
   */
  void setReason(final Integer reason);

  /**
   * Setter for revocation time
   *
   * @param revocationTime revocatioin time
   */
  void setRevocationTime(final Date revocationTime);
}
