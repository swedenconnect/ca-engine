package se.swedenconnect.ca.cmc.api;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmc.*;
import org.bouncycastle.cmc.SimplePKIResponse;
import org.bouncycastle.operator.ContentSigner;
import se.swedenconnect.ca.cmc.api.data.*;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.request.CMCRequestModel;
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
    PKIResponse pkiResponseData = getPKIResponseData(cmcResponseModel);
    List<X509Certificate> cmsCertList = new ArrayList<>(signerCertChain);
    List<X509Certificate> outputCerts = cmcResponseModel.getReturnCertificates();
    if (outputCerts != null) {
      outputCerts.stream().forEach(x509Certificate -> cmsCertList.add(x509Certificate));
    }

    CMCResponse.CMCResponseBuilder responseBuilder = CMCResponse.builder()
      .nonce(cmcResponseModel.getNonce())
      .pkiResponse(pkiResponseData)
      .cmcResponseBytes(CMCUtils.signEncapsulatedCMSContent(CMCObjectIdentifiers.id_cct_PKIResponse, pkiResponseData, cmsCertList, signer));

    return responseBuilder.build();
  }

  private PKIResponse getPKIResponseData(CMCResponseModel cmcResponseModel) {

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

  private List<TaggedAttribute> getControlAttributes(CMCResponseModel cmcResponseModel) {

    List<TaggedAttribute> taggedAttributeList = new ArrayList<>();
    CMCRequestFactory.addNonceControl(taggedAttributeList, cmcResponseModel.getNonce());
    // Add response status and fail info
    addStatusControl(taggedAttributeList, cmcResponseModel);

    // Add response info data
    final byte[] responseInfo = cmcResponseModel.getResponseInfo();
    if (responseInfo != null) {
      taggedAttributeList.add(CMCRequestFactory.getControl(CMCObjectIdentifiers.id_cmc_responseInfo, new DEROctetString(responseInfo)));
    }
    return taggedAttributeList;
  }

  private void addStatusControl(List<TaggedAttribute> taggedAttributeList, CMCResponseModel cmcResponseModel) {
    CMCResponseStatus cmcResponseStatus = cmcResponseModel.getCmcResponseStatus();
    CMCStatusType cmcStatusType = cmcResponseStatus.getStatus();
    CMCFailType cmcFailType = cmcResponseStatus.getFailType();
    CMCStatusInfoV2Builder statusBuilder = new CMCStatusInfoV2Builder(cmcStatusType.getCmcStatus(),
      CMCRequestFactory.getBodyPartId());
    if (!cmcStatusType.equals(CMCStatusType.success) && cmcFailType != null) {
      statusBuilder.setOtherInfo(cmcFailType.getCmcFailInfo());
    }
    taggedAttributeList.add(CMCRequestFactory.getControl(CMCObjectIdentifiers.id_cmc_statusInfoV2, statusBuilder.build()));
  }

}
