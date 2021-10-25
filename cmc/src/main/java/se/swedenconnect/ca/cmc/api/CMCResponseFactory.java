package se.swedenconnect.ca.cmc.api;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmc.*;
import org.bouncycastle.operator.ContentSigner;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.response.CMCResponseModel;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCResponseFactory {

  private final List<X509Certificate> signerCertChain;
  private final ContentSigner signer;

  public CMCResponseFactory(List<X509Certificate> signerCertChain, ContentSigner signer) {
    this.signerCertChain = signerCertChain;
    this.signer = signer;
  }

  public CMCResponse getCMCResponse(CMCResponseModel cmcResponseModel) throws IOException {
    try {
      PKIResponse pkiResponseData = getPKIResponseData(cmcResponseModel);
      List<X509Certificate> cmsCertList = new ArrayList<>(signerCertChain);
      List<X509Certificate> outputCerts = cmcResponseModel.getReturnCertificates();
      if (outputCerts != null) {
        outputCerts.stream().forEach(x509Certificate -> cmsCertList.add(x509Certificate));
      } else {
        outputCerts = new ArrayList<>();
      }

      CMCResponse.CMCResponseBuilder responseBuilder = CMCResponse.builder()
        .nonce(cmcResponseModel.getNonce())
        .pkiResponse(pkiResponseData)
        .cmcResponseBytes(CMCUtils.signEncapsulatedCMSContent(CMCObjectIdentifiers.id_cct_PKIResponse, pkiResponseData, cmsCertList, signer))
        .returnCertificates(outputCerts)
        .responseStatus(cmcResponseModel.getCmcResponseStatus())
        .cmcRequestType(cmcResponseModel.getCmcRequestType());

      return responseBuilder.build();
    } catch (Exception ex) {
      throw new IOException("Error creating CMC Response", ex);
    }
  }

  private PKIResponse getPKIResponseData(CMCResponseModel cmcResponseModel) throws Exception{

    ASN1EncodableVector pkiResponseSeq = new ASN1EncodableVector();
    ASN1EncodableVector controlSeq = new ASN1EncodableVector();
    ASN1EncodableVector cmsSeq = new ASN1EncodableVector();
    ASN1EncodableVector otherMsgSeq = new ASN1EncodableVector();

    List<TaggedAttribute> controlAttrList = getControlAttributes(cmcResponseModel);
    for (TaggedAttribute contrAttr : controlAttrList) {
      controlSeq.add(contrAttr.toASN1Primitive());
    }
    pkiResponseSeq.add(new DERSequence(controlSeq));
    pkiResponseSeq.add(new DERSequence(cmsSeq));
    pkiResponseSeq.add(new DERSequence(otherMsgSeq));

    PKIResponse pkiResponse = PKIResponse.getInstance(new DERSequence(pkiResponseSeq));
    return pkiResponse;
  }

  private List<TaggedAttribute> getControlAttributes(CMCResponseModel cmcResponseModel)  throws Exception {

    List<TaggedAttribute> taggedAttributeList = new ArrayList<>();
    addNonceControl(taggedAttributeList, cmcResponseModel.getNonce());
    // Add response status and fail info
    addStatusControl(taggedAttributeList, cmcResponseModel);

    // Add response info data
    final byte[] responseInfo = cmcResponseModel.getResponseInfo();
    if (responseInfo != null) {
      taggedAttributeList.add(CMCRequestFactory.getControl(CMCObjectIdentifiers.id_cmc_responseInfo, new DEROctetString(responseInfo)));
    }
    return taggedAttributeList;
  }

  public static void addNonceControl(List<TaggedAttribute> taggedAttributeList, byte[] nonce) {
    if (nonce != null) {
      taggedAttributeList.add(CMCRequestFactory.getControl(CMCObjectIdentifiers.id_cmc_recipientNonce, new DEROctetString(nonce)));
    }
  }



  private void addStatusControl(List<TaggedAttribute> taggedAttributeList, CMCResponseModel cmcResponseModel) throws Exception {
    CMCResponseStatus cmcResponseStatus = cmcResponseModel.getCmcResponseStatus();
    CMCStatusType cmcStatusType = cmcResponseStatus.getStatus();
    CMCFailType cmcFailType = cmcResponseStatus.getFailType();
    String message = cmcResponseStatus.getMessage();
    CMCStatusInfoV2Builder statusBuilder = new CMCStatusInfoV2Builder(cmcStatusType.getCmcStatus(),
      cmcResponseStatus.getBodyPartIDList().toArray(new BodyPartID[0]));
    if (!cmcStatusType.equals(CMCStatusType.success) && cmcFailType != null) {
      statusBuilder.setOtherInfo(cmcFailType.getCmcFailInfo());
    }
    if (message != null) {
      statusBuilder.setStatusString(message);
    }
    taggedAttributeList.add(CMCRequestFactory.getControl(CMCObjectIdentifiers.id_cmc_statusInfoV2, statusBuilder.build()));
  }

}
