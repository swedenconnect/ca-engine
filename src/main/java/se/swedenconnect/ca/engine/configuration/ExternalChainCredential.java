package se.swedenconnect.ca.engine.configuration;

import se.swedenconnect.security.credential.PkiCredential;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Implements a PkiCredential that use an inner base credential to store the private key only
 * and provides the ability to freely set and change the certificate chain associated with that
 * private key.
 *
 * <p>
 * This implementation of PkiCredential is important when setting up a CA or OCSP where we may
 * have to set the chain from another source than the key store or the HSM holding the private key.
 * </p>
 *
 * <p>
 * This implementation is not necessarily used as a bean that is wired into the system as a preconfigured credential.
 * On the contrary, this credential is normally used when the credential is setup in steps before it is ready to
 * be used. Example:
 * </p>
 *
 * <ul>
 *   <li>The credential is first initiated with the key and certificate from a hsm slot</li>
 *   <li>Then the credential is used to issue a new self-issued certificate suitable for the service</li>
 *   <li>The self issued certificate is replacing the first chain of this credential</li>
 *   <li>The self issued certificate is sent to another CA to be certified</li>
 *   <li>The credential is updated with the resulting chain</li>
 * </ul>
 *
 * <p>
 *   This is the main reason why this credential both sets the chain at construction and has setters for the same data
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExternalChainCredential implements PkiCredential {

  private List<X509Certificate> certificateChain;
  private final PkiCredential baseCredential;

  /**
   * Constructor providing an external chain credential from a base credential only
   *
   * @param baseCredential a base credential holding a private and a public key
   */
  public ExternalChainCredential(PkiCredential baseCredential) {
    this(null, baseCredential);
  }

  /**
   * Constructor for the external chain credential
   *
   * @param certificateChain an optional external certificate chain to associate with this credential private key
   * @param baseCredential the base credential holding a public and private key
   */
  public ExternalChainCredential(List<X509Certificate> certificateChain,
    PkiCredential baseCredential) {
    // As prio 1 we set any externally specified chain
    this.certificateChain = certificateChain == null ? new ArrayList<>() : certificateChain;
    this.baseCredential = baseCredential;
    if (this.certificateChain.isEmpty()){
      // If not certificate chain was set. Attempt to import any chain from the base credential
      this.certificateChain = baseCredential.getCertificateChain();
    }
    // This credential must be ready to use ofter construction. We therefore make the basic checks
    // already at this point
    try {
      afterPropertiesSet();
    }
    catch (Exception e) {
      throw new IllegalArgumentException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public PublicKey getPublicKey() {
    return certificateChain.get(0).getPublicKey();
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate getCertificate() {
    return certificateChain.get(0);
  }

  /** {@inheritDoc} */
  @Override
  public void setCertificate(X509Certificate x509Certificate) {
    Objects.requireNonNull(x509Certificate, "Certificate must not be null");
    this.certificateChain = List.of(x509Certificate);
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getCertificateChain() {
    return certificateChain;
  }

  /** {@inheritDoc} */
  @Override
  public void setCertificateChain(List<X509Certificate> certificateChain) {
    Objects.requireNonNull(certificateChain, "Certificate chain must not be null");
    if (certificateChain.isEmpty()){
      throw new IllegalArgumentException("Certificate chain must not be empty");
    }
    this.certificateChain = certificateChain;
  }

  /** {@inheritDoc} */
  @Override
  public PrivateKey getPrivateKey() {
    return baseCredential.getPrivateKey();
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    X509Certificate cert = this.getCertificate();
    if (cert != null) {
      return cert.getSubjectX500Principal().getName();
    } else {
      PublicKey key = this.getPublicKey();
      return key != null ? String.format("%s-%s", key.getAlgorithm(), UUID.randomUUID()) : "ExtendedCredential-" + UUID.randomUUID().toString();
    }
  }

  /** {@inheritDoc} */
  @Override
  public void destroy() throws Exception {
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    if (this.getPublicKey() == null) {
      throw new IllegalArgumentException("Either 'certificate'/'certificates' or 'publicKey' must be assigned");
    } else if (getPrivateKey() == null) {
      throw new IllegalArgumentException("Property 'privateKey' must be assigned");
    }
  }
}
