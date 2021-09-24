package se.swedenconnect.ca.cmc.model.impl;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.operator.ContentSigner;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.CMCRequestModel;
import se.swedenconnect.ca.cmc.model.CMCRequestType;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Abstract implementation of the CMC request model
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractCMCRequestModel implements CMCRequestModel {

  private static final SecureRandom RNG = CMCUtils.RNG;

  public AbstractCMCRequestModel(CMCRequestType cmcRequestType, ContentSigner cmcSigner, List<X509Certificate> cmcSignerCerts) {
    this(cmcRequestType, cmcSigner, cmcSignerCerts, null);
  }

  public AbstractCMCRequestModel(CMCRequestType cmcRequestType, ContentSigner cmcSigner, List<X509Certificate> cmcSignerCerts, byte[] registrationInfo) {
    this.registrationInfo = registrationInfo;
    this.cmcRequestType = cmcRequestType;
    this.cmcSigner = cmcSigner;
    this.cmcSignerCerts = cmcSignerCerts;
    this.nonce = new byte[128];
    RNG.nextBytes(nonce);
  }

  @Getter @Setter protected byte[] nonce;
  @Getter @Setter protected byte[] registrationInfo;
  @Getter protected CMCRequestType cmcRequestType;
  @Getter protected ContentSigner cmcSigner;
  @Getter protected List<X509Certificate> cmcSignerCerts;



}
