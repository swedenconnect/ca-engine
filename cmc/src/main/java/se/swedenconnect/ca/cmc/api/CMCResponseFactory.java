/*
 * Copyright (c) 2021. Agency for Digital Government (DIGG)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.swedenconnect.ca.cmc.api;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmc.*;
import org.bouncycastle.operator.ContentSigner;
import se.swedenconnect.ca.cmc.api.data.*;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.response.CMCResponseModel;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * This class is intended to be used as a bean for creating CMC responses
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCResponseFactory {

  /** Signer certificate chain for signing CMC requests */
  private final List<X509Certificate> signerCertChain;
  /** A CMS Content signer used to sign CMC requests */
  private final ContentSigner signer;

  /**
   * Constructor
   * @param signerCertChain signer certificate chain for signing CMC requests
   * @param signer a CMS Content signer used to sign CMC requests
   */
  public CMCResponseFactory(List<X509Certificate> signerCertChain, ContentSigner signer) {
    this.signerCertChain = signerCertChain;
    this.signer = signer;
  }

  /**
   * Create a CMC response
   * @param cmcResponseModel response model holding data necessary to create the CMC response
   * @return {@link CMCResponse}
   * @throws IOException on errors creating a CMC response
   */
  public CMCResponse getCMCResponse(CMCResponseModel cmcResponseModel) throws IOException {
    try {
      PKIResponse pkiResponseData = getPKIResponseData(cmcResponseModel);
      List<X509Certificate> cmsCertList = new ArrayList<>(signerCertChain);
      List<X509Certificate> outputCerts = cmcResponseModel.getReturnCertificates();
      if (outputCerts != null) {
        cmsCertList.addAll(outputCerts);
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

    return PKIResponse.getInstance(new DERSequence(pkiResponseSeq));
  }

  private List<TaggedAttribute> getControlAttributes(CMCResponseModel cmcResponseModel)  {

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



  private void addStatusControl(List<TaggedAttribute> taggedAttributeList, CMCResponseModel cmcResponseModel) {
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
