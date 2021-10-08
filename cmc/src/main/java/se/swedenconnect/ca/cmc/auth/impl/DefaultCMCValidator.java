package se.swedenconnect.ca.cmc.auth.impl;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Provides a default CMC validator that validates the CMC signature based on a set of trusted certificates.
 * This validator requires the CMC to be signed by a single certificate.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultCMCValidator extends AbstractCMCValidator{

  private final List<X509CertificateHolder> trustedCMCSigners;

  /**
   * Constructor for a default CMC Signature validator
   * @param trustedCMCSigners trusted CMC signer certificates
   * @throws CertificateEncodingException on errors parsing the provided certificates
   */
  public DefaultCMCValidator(X509Certificate... trustedCMCSigners) throws CertificateEncodingException {
    this.trustedCMCSigners = new ArrayList();
    for (X509Certificate cert : trustedCMCSigners) {
      this.trustedCMCSigners.add(new JcaX509CertificateHolder(cert));
    }
  }

  /**
   * Constructor for a default CMC Signature validator
   * @param trustedCMCSigners trusted CMC signer certificates
   */
  public DefaultCMCValidator(X509CertificateHolder... trustedCMCSigners) {
    this.trustedCMCSigners = Arrays.asList(trustedCMCSigners);
  }

  /** {@inheritDoc} */
  @Override protected List<X509CertificateHolder> verifyCMSSignature(CMSSignedData cmsSignedData)
    throws Exception {
    Collection<X509CertificateHolder> certsInCMS = cmsSignedData.getCertificates().getMatches(null);
    X509CertificateHolder trustedSignerCert = getTrustedSignerCert(certsInCMS);
    SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder().build(trustedSignerCert);
    SignerInformation signerInformation = cmsSignedData.getSignerInfos().iterator().next();
    signerInformation.verify(signerInformationVerifier);
    return Arrays.asList(trustedSignerCert);
  }

  private X509CertificateHolder getTrustedSignerCert(Collection<X509CertificateHolder> certsInCMS)
    throws CertificateException, OperatorCreationException {
    Iterator<X509CertificateHolder> iterator = certsInCMS.iterator();
    while (iterator.hasNext()) {
      for (X509CertificateHolder trustedCMCSigner : trustedCMCSigners) {
        if (trustedCMCSigner.equals(iterator.next())) {
          return trustedCMCSigner;
        }
      }
    }
    throw new IllegalArgumentException("No trusted certificate found in signed CMC");
  }

}
