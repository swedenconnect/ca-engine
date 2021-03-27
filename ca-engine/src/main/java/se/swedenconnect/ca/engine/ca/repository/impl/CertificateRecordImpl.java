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

package se.swedenconnect.ca.engine.ca.repository.impl;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;

import java.math.BigInteger;
import java.util.Date;

/**
 * Data class defining the default content of a CA record
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
@AllArgsConstructor
public class CertificateRecordImpl implements CertificateRecord {

  /** The byes of the issued certificate */
  protected byte[] certificate;
  /** The serial number of the issued certificate */
  protected BigInteger serialNumber;
  /** The issue time of the certificate */
  protected Date issueDate;
  /** The expiry date of the certificate */
  protected Date expiryDate;
  /** Boolean indicator if this certificate is revoked */
  protected boolean revoked;
  /** Revocation reason if applicable */
  protected Integer reason;
  /** Time of revocation if applicable */
  protected Date revocationTime;

  /** {@inheritDoc} */
  @Override public byte[] getCertificate() {
    return certificate;
  }

  /** {@inheritDoc} */
  @Override public void setCertificate(byte[] certificate) {
    this.certificate = certificate;
  }

  /** {@inheritDoc} */
  @Override public BigInteger getSerialNumber() {
    return serialNumber;
  }

  /** {@inheritDoc} */
  @Override public void setSerialNumber(BigInteger serialNumber) {
    this.serialNumber = serialNumber;
  }

  /** {@inheritDoc} */
  @Override public Date getIssueDate() {
    return issueDate;
  }

  /** {@inheritDoc} */
  @Override public void setIssueDate(Date issueDate) {
    this.issueDate = issueDate;
  }

  /** {@inheritDoc} */
  @Override public Date getExpiryDate() {
    return expiryDate;
  }

  /** {@inheritDoc} */
  @Override public void setExpiryDate(Date expiryDate) {
    this.expiryDate = expiryDate;
  }

  /** {@inheritDoc} */
  @Override public boolean isRevoked() {
    return revoked;
  }

  /** {@inheritDoc} */
  @Override public void setRevoked(boolean revoked) {
    this.revoked = revoked;
  }

  /** {@inheritDoc} */
  @Override public Integer getReason() {
    return reason;
  }

  /** {@inheritDoc} */
  @Override public void setReason(Integer reason) {
    this.reason = reason;
  }

  /** {@inheritDoc} */
  @Override public Date getRevocationTime() {
    return revocationTime;
  }

  /** {@inheritDoc} */
  @Override public void setRevocationTime(Date revocationTime) {
    this.revocationTime = revocationTime;
  }
}
