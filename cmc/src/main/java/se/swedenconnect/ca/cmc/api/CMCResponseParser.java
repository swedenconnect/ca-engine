package se.swedenconnect.ca.cmc.api;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.asn1.cmc.PKIResponse;
import org.bouncycastle.asn1.cmc.TaggedAttribute;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.auth.CMCValidationResult;
import se.swedenconnect.ca.cmc.auth.CMCValidator;
import se.swedenconnect.ca.engine.utils.CAUtils;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMCResponseParser {

  private final CMCValidator validator;

  public CMCResponseParser(CMCValidator validator) {
    this.validator = validator;
  }

  public CMCResponse parseCMCresponse(byte[] cmcResponseBytes) throws IOException {
    CMCResponse.CMCResponseBuilder responseBuilder = CMCResponse.builder();
    responseBuilder.cmcResponseBytes(cmcResponseBytes);

    CMCValidationResult cmcValidationResult = validator.validateCMC(cmcResponseBytes);
    if (!CMCObjectIdentifiers.id_cct_PKIResponse.equals(cmcValidationResult.getContentType())) {
      throw new IOException("Illegal CMS content type for CMC request");
    }

    try {
      CMSSignedData signedData = cmcValidationResult.getSignedData();
      PKIResponse pkiResponse = PKIResponse.getInstance(new ASN1InputStream((byte[]) signedData.getSignedContent().getContent()).readObject());
      responseBuilder.pkiResponse(pkiResponse);
      TaggedAttribute[] responseControlSequence = CMCUtils.getResponseControlSequence(pkiResponse);
      byte[] nonce = (byte[]) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_recipientNonce, responseControlSequence).getValue();
      responseBuilder
        .nonce(nonce)
        .returnCertificates(getResponseCertificates(signedData));
    } catch (Exception ex){
      log.debug("Error parsing PKIResponse Data from CMC response", ex.toString());
      throw new IOException("Error parsing PKIResponse Data from CMC response", ex);
    }
    return responseBuilder.build();
  }

  private List<X509Certificate> getResponseCertificates(CMSSignedData signedData) throws CertificateException, IOException {
    Collection<X509CertificateHolder> certsInCMS = signedData.getCertificates().getMatches(null);
    List<X509Certificate> certificateList = new ArrayList<>();
    for (X509CertificateHolder certificateHolder: certsInCMS){
      certificateList.add(CAUtils.getCert(certificateHolder));
    }
    return certificateList;
  }

}
