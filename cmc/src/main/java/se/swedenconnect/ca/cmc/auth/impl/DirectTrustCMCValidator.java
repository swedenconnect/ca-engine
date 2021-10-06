package se.swedenconnect.ca.cmc.auth.impl;

import lombok.extern.log4j.Log4j2;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import se.swedenconnect.ca.cmc.auth.CMCValidationResult;
import se.swedenconnect.ca.cmc.auth.CMCValidator;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DirectTrustCMCValidator implements CMCValidator {

  private final List<X509CertificateHolder> trustedCMCSigners;

  public DirectTrustCMCValidator(X509Certificate... trustedCMCSigners) throws CertificateEncodingException {
    this.trustedCMCSigners = new ArrayList();
    for (X509Certificate cert : trustedCMCSigners) {
      this.trustedCMCSigners.add(new JcaX509CertificateHolder(cert));
    }
  }

  public DirectTrustCMCValidator(X509CertificateHolder... trustedCMCSigners) {
    this.trustedCMCSigners = Arrays.asList(trustedCMCSigners);
  }

  @Override public CMCValidationResult validateCMC(byte[] cmcMessage) {

    CMCValidationResult result = new CMCValidationResult();
    if (isSimpleCMCResponse(result, cmcMessage)) {
      return result;
    }

    try {
      CMSSignedData cmsSignedData = new CMSSignedData(cmcMessage);
      ASN1ObjectIdentifier contentType = cmsSignedData.getSignedContent().getContentType();
      if (contentType.equals(CMCObjectIdentifiers.id_cct_PKIData) || contentType.equals(CMCObjectIdentifiers.id_cct_PKIResponse)) {
        result.setContentType(contentType);
      }
      else {
        result.setValid(false);
        result.setErrorMessage("Illegal CMC data content type");
        result.setException(new IOException("Illegal CMC data content type"));
        return result;
      }
      result.setSignedData(cmsSignedData);

      Collection<X509CertificateHolder> certsInCMS = cmsSignedData.getCertificates().getMatches(null);
      X509CertificateHolder trustedSignerCert = getTrustedSignerCert(certsInCMS);
      SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder().build(trustedSignerCert);
      SignerInformation signerInformation = cmsSignedData.getSignerInfos().iterator().next();
      signerInformation.verify(signerInformationVerifier);
      // Set result conclusion
      result.setSignerCertificatePath(Arrays.asList(trustedSignerCert));
      result.setSimpleResponse(false);
      result.setValid(true);
    }
    catch (Exception ex) {
      result.setValid(false);
      result.setException(ex);
      result.setErrorMessage("CMC signature validation failed");
    }

    return result;
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

  private boolean isSimpleCMCResponse(CMCValidationResult result, byte[] cmcMessage) {
    List<X509CertificateHolder> certificateList = new ArrayList<>();

    try {
      ASN1InputStream ain = new ASN1InputStream(cmcMessage);
      ContentInfo cmsContentInfo = ContentInfo.getInstance(ain.readObject());
      if (!cmsContentInfo.getContentType().equals(CMSObjectIdentifiers.signedData)) {
        // The Body of the CMS ContentInfo MUST be SignedData
        return false;
      }
      SignedData signedData = SignedData.getInstance(cmsContentInfo.getContent());
      ASN1Set signerInfos = signedData.getSignerInfos();
      if (signerInfos !=  null && signerInfos.size()>0){
        // This is not a simple response if signerInfos is present
        return false;
      }
      // This is a simple response
      return true;
    } catch (Exception ex){
      log.debug("Failed to parse response as valid CMS data");
      return false;
    }
  }
}
