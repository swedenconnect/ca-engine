package se.swedenconnect.ca.cmc.model.response.impl;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.operator.ContentSigner;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.cmc.model.response.CMCResponseModel;

import java.security.SecureRandom;
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

  public AbstractCMCResponseModel(byte[] nonce, CMCResponseStatus cmcResponseStatus) {
    this(nonce, cmcResponseStatus, null);
  }

  public AbstractCMCResponseModel(byte[] nonce, CMCResponseStatus cmcResponseStatus,
    byte[] responseInfo) {
    this.nonce = nonce;
    this.responseInfo = responseInfo;
    this.cmcResponseStatus = cmcResponseStatus;
    this.returnCertificates = new ArrayList<>();
  }

  @Getter @Setter protected byte[] nonce;
  @Getter @Setter protected byte[] responseInfo;
  @Getter @Setter protected List<X509Certificate> returnCertificates;
  @Getter protected CMCResponseStatus cmcResponseStatus;
}
