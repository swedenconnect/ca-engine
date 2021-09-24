package se.swedenconnect.ca.cmc.ca;

/**
 * Enumeration of functional profiles for certificate validators
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public enum ValidatorProfile {

  /** Normal operation where all validators are responsive to requests */
  NORMAL,
  /** Certificate validators do not respond to CRL download or OCSP requests */
  NONE_RESPONSIVE;
}
