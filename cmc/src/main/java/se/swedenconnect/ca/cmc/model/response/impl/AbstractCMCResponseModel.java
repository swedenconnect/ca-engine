package se.swedenconnect.ca.cmc.model.response.impl;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.asn1.cmc.BodyPartID;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
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

  public AbstractCMCResponseModel(byte[] nonce, CMCResponseStatus cmcResponseStatus, List<BodyPartID> processedRequestObjects) {
    this(nonce, cmcResponseStatus, processedRequestObjects, null);
  }

  public AbstractCMCResponseModel(byte[] nonce, CMCResponseStatus cmcResponseStatus, List<BodyPartID> processedRequestObjects,
    byte[] responseInfo) {
    this.nonce = nonce;
    this.responseInfo = responseInfo;
    this.cmcResponseStatus = cmcResponseStatus;
    this.returnCertificates = new ArrayList<>();
    this.processedRequestObjects = processedRequestObjects;
  }

  @Getter @Setter protected byte[] nonce;
  @Getter @Setter protected byte[] responseInfo;
  @Getter @Setter protected List<X509Certificate> returnCertificates;
  @Getter protected CMCResponseStatus cmcResponseStatus;
  @Getter protected List<BodyPartID> processedRequestObjects;
}
