package se.swedenconnect.ca.cmc.api;

import lombok.Getter;
import org.bouncycastle.asn1.cmc.PKIResponse;
import se.swedenconnect.ca.cmc.auth.CMCValidator;
import se.swedenconnect.ca.cmc.model.CMCRequestModel;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCResponse {

  @Getter private byte[] cmcResponseBytes;
  @Getter private byte[] nonce;
  @Getter List<X509Certificate> returnCertificates;
  @Getter PKIResponse pkiResponse;


  /**
   * Constructor from CMC Request bytes
   * @param cmcResponseBytes the bytes of a CMC request
   * @param validator validator for validating the signature of the CMC request and authorization to sign request
   * @throws IOException on error parsing the CMC request
   */
  public CMCResponse(byte[] cmcResponseBytes, CMCValidator validator) throws IOException {
    this.cmcResponseBytes = cmcResponseBytes;
    parseResponse(validator);
  }

  /**
   * Constructor from CMC Response model data
   * @param cmcRequestModel CMC Request model data
   * @throws IOException on error building a CMC request from the model data
   */
  public CMCResponse(CMCRequestModel cmcRequestModel) throws IOException {

  }

  private void parseResponse(CMCValidator validator) {
  }




}
