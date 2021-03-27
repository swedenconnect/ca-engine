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

import lombok.NoArgsConstructor;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;

import java.math.BigInteger;
import java.util.Date;

/**
 * Certificate record implementation with data stored in objects that are easier to serialize e.g. using a JSON serializer.
 *
 * This is done by converting Date to long and BigInteger to string.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
public class SerializableCertificateRecord implements CertificateRecord {

  /** The bytes of the issued certificate */
  protected byte[] certificate;
  /** The serial number of the issued certificate */
  protected String serialNumber;
  /** The issue time of the certificate */
  protected long issueDate;
  /** The expiry date of the certificate */
  protected long expiryDate;
  /** Boolean indicator if this certificate is revoked */
  protected boolean revoked;
  /** Revocation reason if applicable */
  protected Integer reason;
  /** Time of revocation if applicable */
  protected long revocationTime;

  /**
   * Constructor for serializable certificate record
   * @param certificate the bytes of the issued certificate
   * @param serialNumber The serial number of the issued certificate
   * @param issueDate the issue time of the certificate
   * @param expiryDate the expiry date of the certificate
   * @param revoked boolean indicator if this certificate is revoked
   * @param reason revocation reason if applicable
   * @param revocationTime time of revocation if applicable
   */
  public SerializableCertificateRecord(byte[] certificate, BigInteger serialNumber, Date issueDate, Date expiryDate, boolean revoked,
    Integer reason, Date revocationTime) {
    setCertificate(certificate);
    setSerialNumber(serialNumber);
    setIssueDate(issueDate);
    setExpiryDate(expiryDate);
    setRevoked(revoked);
    setReason(reason);
    setRevocationTime(revocationTime);
  }

  /** {@inheritDoc} */
  @Override public byte[] getCertificate() {
    return certificate;
  }

  /** {@inheritDoc} */
  @Override public BigInteger getSerialNumber() {
    return serialNumber == null ? null : new BigInteger(serialNumber);
  }

  /** {@inheritDoc} */
  @Override public Date getIssueDate() {
    return getDateOrNull(issueDate);
  }

  /** {@inheritDoc} */
  @Override public Date getExpiryDate() {
    return getDateOrNull(expiryDate);
  }

  /** {@inheritDoc} */
  @Override public boolean isRevoked() {
    return revoked;
  }

  /** {@inheritDoc} */
  @Override public Integer getReason() {
    return reason;
  }

  /** {@inheritDoc} */
  @Override public Date getRevocationTime() {
    return getDateOrNull(revocationTime);
  }

  /** {@inheritDoc} */
  @Override public void setCertificate(byte[] certificate) {
    this.certificate = certificate;
  }

  /** {@inheritDoc} */
  @Override public void setSerialNumber(BigInteger serialNumber) {
    this.serialNumber = serialNumber == null ? null : serialNumber.toString();
  }

  /** {@inheritDoc} */
  @Override public void setIssueDate(Date issueDate) {
    this.issueDate = parseDateOrNull(issueDate);
  }

  /** {@inheritDoc} */
  @Override public void setExpiryDate(Date expiryDate) {
    this.expiryDate = parseDateOrNull(expiryDate);
  }

  /** {@inheritDoc} */
  @Override public void setRevoked(boolean revoked) {
    this.revoked = revoked;
  }

  /** {@inheritDoc} */
  @Override public void setReason(Integer reason) {
    this.reason = reason;
  }

  /** {@inheritDoc} */
  @Override public void setRevocationTime(Date revocationTime) {
    this.revocationTime = parseDateOrNull(revocationTime);
  }

  private long parseDateOrNull(Date revocationTime) {
    return revocationTime == null ? -1 : revocationTime.getTime();
  }

  private Date getDateOrNull(long longTime) {
    return longTime < 0 ? null : new Date(longTime);
  }

}
