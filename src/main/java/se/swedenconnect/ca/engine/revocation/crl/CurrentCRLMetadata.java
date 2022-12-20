package se.swedenconnect.ca.engine.revocation.crl;

import java.math.BigInteger;
import java.time.Instant;

import lombok.Data;

/**
 * Metadata for the most recent CRL issued by any of the instances serving the same CA identity.
 * This takes into account a deployment scenario where multiple instances of the same CA
 * cooperates to provide a unified revocation experience where these data are synchronized and
 * shared among the instances.
 *
 * The data provided here reflects the latest CRL update made by any instance and allows
 * other instances to choose to issue a CRL with identical metadata or to opt for issuance
 * of a new CRL and thus also update and share an updated version of this metadata, allowing
 * other instances to follow.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CurrentCRLMetadata {

  /**
   * Get CRL number of the latest published CRL
   * @return CRL Number
   */
  BigInteger getCrlNumber();

  /**
   * Issue time of the latest published CRL
   * @return issue time
   */
  Instant getIssueTime();

  /**
   * Next update time of the latest published CRL
   * @return update time
   */
  Instant getNextUpdate();

  /**
   * Revoked certificate count of the latest published CRL
   * @return revoked certificate count
   */
  int getRevokedCertCount();

}
