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
package se.swedenconnect.ca.engine.ca.repository.impl;

import java.math.BigInteger;
import java.util.Date;

import lombok.NoArgsConstructor;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;

/**
 * Certificate record implementation with data stored in objects that are easier to serialize e.g. using a JSON
 * serializer.
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
   * Constructor for serializable certificate record.
   *
   * @param certificate the bytes of the issued certificate
   * @param serialNumber The serial number of the issued certificate
   * @param issueDate the issue time of the certificate
   * @param expiryDate the expiry date of the certificate
   * @param revoked boolean indicator if this certificate is revoked
   * @param reason revocation reason if applicable
   * @param revocationTime time of revocation if applicable
   */
  public SerializableCertificateRecord(final byte[] certificate, final BigInteger serialNumber, final Date issueDate,
      final Date expiryDate, final boolean revoked, final Integer reason, final Date revocationTime) {
    this.setCertificate(certificate);
    this.setSerialNumber(serialNumber);
    this.setIssueDate(issueDate);
    this.setExpiryDate(expiryDate);
    this.setRevoked(revoked);
    this.setReason(reason);
    this.setRevocationTime(revocationTime);
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getCertificate() {
    return this.certificate;
  }

  /** {@inheritDoc} */
  @Override
  public BigInteger getSerialNumber() {
    return this.serialNumber == null ? null : new BigInteger(this.serialNumber);
  }

  /** {@inheritDoc} */
  @Override
  public Date getIssueDate() {
    return this.getDateOrNull(this.issueDate);
  }

  /** {@inheritDoc} */
  @Override
  public Date getExpiryDate() {
    return this.getDateOrNull(this.expiryDate);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isRevoked() {
    return this.revoked;
  }

  /** {@inheritDoc} */
  @Override
  public Integer getReason() {
    return this.reason;
  }

  /** {@inheritDoc} */
  @Override
  public Date getRevocationTime() {
    return this.getDateOrNull(this.revocationTime);
  }

  /** {@inheritDoc} */
  @Override
  public void setCertificate(final byte[] certificate) {
    this.certificate = certificate;
  }

  /** {@inheritDoc} */
  @Override
  public void setSerialNumber(final BigInteger serialNumber) {
    this.serialNumber = serialNumber == null ? null : serialNumber.toString();
  }

  /** {@inheritDoc} */
  @Override
  public void setIssueDate(final Date issueDate) {
    this.issueDate = this.parseDateOrNull(issueDate);
  }

  /** {@inheritDoc} */
  @Override
  public void setExpiryDate(final Date expiryDate) {
    this.expiryDate = this.parseDateOrNull(expiryDate);
  }

  /** {@inheritDoc} */
  @Override
  public void setRevoked(final boolean revoked) {
    this.revoked = revoked;
  }

  /** {@inheritDoc} */
  @Override
  public void setReason(final Integer reason) {
    this.reason = reason;
  }

  /** {@inheritDoc} */
  @Override
  public void setRevocationTime(final Date revocationTime) {
    this.revocationTime = this.parseDateOrNull(revocationTime);
  }

  private long parseDateOrNull(final Date revocationTime) {
    return revocationTime == null ? -1 : revocationTime.getTime();
  }

  private Date getDateOrNull(final long longTime) {
    return longTime < 0 ? null : new Date(longTime);
  }

}
