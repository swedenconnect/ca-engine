package se.swedenconnect.ca.cmc.auth.impl;

import lombok.extern.slf4j.Slf4j;
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
public abstract class AbstractCMCValidator implements CMCValidator {

  public AbstractCMCValidator() {
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
      List<X509CertificateHolder> trustedSignerCertChain = verifyCMSSignature(cmsSignedData);
      // Set result conclusion
      result.setSignerCertificatePath(trustedSignerCertChain);
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

  /**
   * Verifies the CMS signature
   * @param cmsSignedData the signed data to verify
   * @return The signing certificate chain if the verification was successful
   * @throws IOException if signature validation failed
   */
  protected abstract List<X509CertificateHolder> verifyCMSSignature(CMSSignedData cmsSignedData) throws Exception;

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