package se.swedenconnect.ca.cmc.utils;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;

import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCSigner {

  private final KeyPair signerKeyPair;
  private final List<X509Certificate> signerCertChain;
  private final boolean pss;
  private ContentSigner contentSigner;

  public CMCSigner(KeyPair signerKeyPair, X509Certificate signerCert, boolean pss)
    throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, OperatorCreationException {
    this.signerKeyPair = signerKeyPair;
    this.signerCertChain = Arrays.asList(signerCert);
    this.pss = pss;
    setContentSigner();
  }

  public CMCSigner(KeyPair signerKeyPair, X509Certificate signerCert)
    throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, OperatorCreationException {
    this.signerKeyPair = signerKeyPair;
    this.signerCertChain = Arrays.asList(signerCert);
    this.pss = false;
    setContentSigner();
  }

  private void setContentSigner() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, OperatorCreationException {
    PublicKey publicKey = signerKeyPair.getPublic();
    String algo = null;
    if (publicKey instanceof RSAPublicKey) {
      if (pss) {
        algo = CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1;
      } else {
        algo = CAAlgorithmRegistry.ALGO_ID_SIGNATURE_RSA_SHA256;
      }
    } else {
      algo = CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA256;
    }
    contentSigner = new JcaContentSignerBuilder(CAAlgorithmRegistry.getSigAlgoName(algo)).build(signerKeyPair.getPrivate());
  }

  public ContentSigner getContentSigner() {
    return contentSigner;
  }

  public List<X509Certificate> getSignerChain() {
    return signerCertChain;
  }
}
