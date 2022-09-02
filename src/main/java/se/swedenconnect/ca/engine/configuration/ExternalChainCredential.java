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
 * This implementation of PkiCredential is important when setting up a CA or OCSP where we may
 * have to set the chain from another source than the key store or the HSM holding the private key.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExternalChainCredential implements PkiCredential {

  private List<X509Certificate> certificateChain;
  private final PkiCredential baseCredential;

  public ExternalChainCredential(PkiCredential baseCredential) throws Exception {
    this(null, baseCredential);
  }

  public ExternalChainCredential(List<X509Certificate> certificateChain,
    PkiCredential baseCredential) throws Exception {
    this.certificateChain = certificateChain == null ? new ArrayList<>() : certificateChain;
    this.baseCredential = baseCredential;
    init();
  }

  @Override public PublicKey getPublicKey() {
    return certificateChain.get(0).getPublicKey();
  }

  @Override public X509Certificate getCertificate() {
    return certificateChain.get(0);
  }

  @Override public void setCertificate(X509Certificate x509Certificate) {
    Objects.requireNonNull(x509Certificate, "Certificate must not be null");
    this.certificateChain = List.of(x509Certificate);
  }

  @Override public List<X509Certificate> getCertificateChain() {
    return certificateChain;
  }

  @Override public void setCertificateChain(List<X509Certificate> certificateChain) {
    Objects.requireNonNull(certificateChain, "Certificate chain must not be null");
    if (certificateChain.isEmpty()){
      throw new IllegalArgumentException("Certificate chain must not be empty");
    }
    this.certificateChain = certificateChain;
  }

  @Override public PrivateKey getPrivateKey() {
    return baseCredential.getPrivateKey();
  }

  @Override public String getName() {
    X509Certificate cert = this.getCertificate();
    if (cert != null) {
      return cert.getSubjectX500Principal().getName();
    } else {
      PublicKey key = this.getPublicKey();
      return key != null ? String.format("%s-%s", key.getAlgorithm(), UUID.randomUUID()) : "ExtendedCredential-" + UUID.randomUUID().toString();
    }
  }

  @Override public void destroy() throws Exception {
  }

  @Override public void afterPropertiesSet() throws Exception {
    // It is essential for the usage of this credential implementation that the chain can be set at any point
    // Therefore only the private key existence is checked here
    if (getPrivateKey() == null) {
      throw new IllegalArgumentException("Property 'privateKey' must be assigned");
    }
  }
}
