package se.swedenconnect.ca.cmc.model.response.impl;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.engine.utils.CAUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCBasicCMCResponseModel extends AbstractCMCResponseModel {

  public CMCBasicCMCResponseModel(byte[] nonce, CMCResponseStatus cmcResponseStatus, List<BodyPartID> processedRequestObjects, byte[] responseInfo) {
    super(nonce, cmcResponseStatus, processedRequestObjects, responseInfo);
  }

  /**
   *
   * @param nonce
   * @param cmcResponseStatus
   * @param responseInfo
   * @param returnCertificates
   * @throws CertificateException
   * @throws IOException
   */
  public CMCBasicCMCResponseModel(byte[] nonce, CMCResponseStatus cmcResponseStatus, List<BodyPartID> processedRequestObjects, byte[] responseInfo, List<? extends Object> returnCertificates)
    throws CertificateException, IOException {
    super(nonce, cmcResponseStatus, processedRequestObjects, responseInfo);
    addCertificates(returnCertificates);

  }

  private void addCertificates(List<? extends Object> returnCertificates) throws CertificateException, IOException {
    List<X509Certificate> certDataList = new ArrayList<>();
    for (Object o : returnCertificates){
      if (o instanceof X509Certificate) {
        certDataList.add((X509Certificate)o);
        continue;
      }
      if (o instanceof X509CertificateHolder) {
        certDataList.add(CAUtils.getCert((X509CertificateHolder)o));
        continue;
      }
      throw new IOException("Illegal certificate type");
    }
    setReturnCertificates(certDataList);
  }

}
