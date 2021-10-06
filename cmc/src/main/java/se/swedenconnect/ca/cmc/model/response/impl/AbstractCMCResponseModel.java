package se.swedenconnect.ca.cmc.model.response.impl;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.operator.ContentSigner;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.cmc.model.response.CMCResponseModel;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AbstractCMCResponseModel implements CMCResponseModel {

  public AbstractCMCResponseModel(byte[] nonce, CMCRequestType cmcRequestType, ContentSigner cmcSigner, List<X509Certificate> cmcSignerCerts) {
    this(nonce, cmcRequestType, cmcSigner, cmcSignerCerts, null);
  }

  public AbstractCMCResponseModel(byte[] nonce, CMCRequestType cmcRequestType, ContentSigner cmcSigner, List<X509Certificate> cmcSignerCerts, byte[] responseInfo) {
    this.nonce = nonce;
    this.responseInfo = responseInfo;
    this.cmcRequestType = cmcRequestType;
    this.cmcSigner = cmcSigner;
    this.cmcSignerCerts = cmcSignerCerts;
  }


  @Getter @Setter protected byte[] nonce;
  @Getter @Setter protected byte[] responseInfo;
  @Getter protected CMCRequestType cmcRequestType;
  @Getter protected ContentSigner cmcSigner;
  @Getter protected List<X509Certificate> cmcSignerCerts;

}
