package se.swedenconnect.ca.cmc.model.response.impl;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.asn1.cmc.BodyPartID;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.cmc.model.response.CMCResponseModel;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AbstractCMCResponseModel implements CMCResponseModel {

  public AbstractCMCResponseModel(byte[] nonce, CMCResponseStatus cmcResponseStatus, CMCRequestType cmcRequestType) {
    this(nonce, cmcResponseStatus, cmcRequestType,  null);
  }

  public AbstractCMCResponseModel(byte[] nonce, CMCResponseStatus cmcResponseStatus, CMCRequestType cmcRequestType, byte[] responseInfo) {
    this.nonce = nonce;
    this.responseInfo = responseInfo;
    this.cmcResponseStatus = cmcResponseStatus;
    this.returnCertificates = new ArrayList<>();
    this.cmcRequestType = cmcRequestType;
  }

  @Getter @Setter protected byte[] nonce;
  @Getter @Setter protected byte[] responseInfo;
  @Getter @Setter protected List<X509Certificate> returnCertificates;
  @Getter protected CMCResponseStatus cmcResponseStatus;
  @Getter protected CMCRequestType cmcRequestType;
}
