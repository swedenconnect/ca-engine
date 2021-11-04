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

package se.swedenconnect.ca.cmc.auth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmc.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;
import se.swedenconnect.ca.cmc.api.data.CMCControlObject;
import se.swedenconnect.ca.cmc.api.data.CMCControlObjectID;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.admin.response.CAInformation;
import se.swedenconnect.ca.cmc.model.admin.response.CertificateData;
import se.swedenconnect.ca.engine.ca.attribute.AttributeValueEncoder;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.engine.utils.CAUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Utility functions for parsing and creating CMC messages
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMCUtils {

  public static final SecureRandom RNG = new SecureRandom();
  public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  /**
   * Create a CRMF request message builder for a CRMF certificate request
   * @param requestId the ID of the created request
   * @param certificateModel model holding data about the certificate to be issued
   * @param attributeValueEncoder encoder for attribute values
   * @return CRMF request message builder
   * @throws IOException on error creating the builder
   */
  public static CertificateRequestMessageBuilder getCRMFRequestMessageBuilder(BodyPartID requestId, CertificateModel certificateModel, AttributeValueEncoder attributeValueEncoder)
    throws IOException {
    CertificateRequestMessageBuilder crmfBuilder = new CertificateRequestMessageBuilder(new BigInteger(String.valueOf(requestId.getID())));
    crmfBuilder.setSubject(CAUtils.getX500Name(certificateModel.getSubject(), attributeValueEncoder));

    SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
      ASN1Sequence.getInstance(certificateModel.getPublicKey().getEncoded()));
    crmfBuilder.setPublicKey(subjectPublicKeyInfo);

    List<ExtensionModel> extensionModels = certificateModel.getExtensionModels();
    for (ExtensionModel extensionModel: extensionModels){
      List<Extension> extensions = extensionModel.getExtensions();
      for (Extension extension: extensions){
        crmfBuilder.addExtension(extension.getExtnId(), extension.isCritical(), extension.getParsedValue());
      }
    }
    return crmfBuilder;
  }

  /**
   * Creates a PKCS10 request
   * @param certificateModel data about the certificate to be requested
   * @param signer the signer of the PKCS10 request
   * @param attributeValueEncoder attribute value encoder
   * @return PKCS10 request
   * @throws IOException on errors creating the request
   */
  public static CertificationRequest getCertificationRequest(CertificateModel certificateModel, ContentSigner signer, AttributeValueEncoder attributeValueEncoder)
    throws IOException {

    X500Name subjectX500Name = CAUtils.getX500Name(certificateModel.getSubject(), attributeValueEncoder);
    SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
      ASN1Sequence.getInstance(certificateModel.getPublicKey().getEncoded()));

    PKCS10CertificationRequestBuilder p10ReqBuilder = new PKCS10CertificationRequestBuilder(subjectX500Name, subjectPublicKeyInfo);
    ExtensionsGenerator extGen = new ExtensionsGenerator();
    List<ExtensionModel> extensionModels = certificateModel.getExtensionModels();
    for (ExtensionModel extensionModel: extensionModels){
      List<Extension> extensions = extensionModel.getExtensions();
      for (Extension extension: extensions){
        extGen.addExtension(extension);
      }
    }
    p10ReqBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
    PKCS10CertificationRequest pkcs10 = p10ReqBuilder.build(signer);
    return CertificationRequest.getInstance(pkcs10.toASN1Structure().toASN1Primitive());
  }

  public static byte[] signEncapsulatedCMSContent(ASN1ObjectIdentifier contentType, ASN1Encodable content, List<X509Certificate> signerCertChain, ContentSigner signer) throws IOException {
    try {
      final Store<?> certs = new JcaCertStore(signerCertChain);
      final CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
      final org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(
        ASN1Primitive.fromByteArray(signerCertChain.get(0).getEncoded()));
      //final ContentSigner signer = new JcaContentSignerBuilder(CAAlgorithmRegistry.getSigAlgoName(algorithm)).build(signKey);
      final JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build());
      gen.addSignerInfoGenerator(builder.build(signer, new X509CertificateHolder(cert)));
      gen.addCertificates(certs);
      //final CMSTypedData encapsulatedContent = new PKCS7ProcessableObject(contentType, content);
      final CMSProcessableByteArray encapsulatedContent = new CMSProcessableByteArray(contentType, content.toASN1Primitive().getEncoded(ASN1Encoding.DER));
      final CMSSignedData resultSignedData = gen.generate(encapsulatedContent, true);
      return resultSignedData.toASN1Structure().getEncoded(ASN1Encoding.DL);
    }
    catch (GeneralSecurityException | CMSException | OperatorCreationException e) {
      final String msg = String.format("Failed to sign content - %s", e.getMessage());
      log.error("{}", msg, e);
      throw new IOException(msg, e);
    }
  }

  public static CMCControlObject getCMCControlObject(ASN1ObjectIdentifier asn1controlOid, PKIResponse pkiResponse)
    throws IOException {
    return getCMCControlObject(asn1controlOid, getResponseControlSequence(pkiResponse));

  }
  public static CMCControlObject getCMCControlObject(ASN1ObjectIdentifier asn1controlOid, PKIData pkiData)
    throws IOException {
    TaggedAttribute[] controlSequence = pkiData.getControlSequence();
    return getCMCControlObject(asn1controlOid, controlSequence);
  }

  private static CMCControlObject getCMCControlObject(ASN1ObjectIdentifier asn1controlOid, TaggedAttribute[] controlSequence)
    throws IOException {
    CMCControlObjectID controlOid = CMCControlObjectID.getControlObjectID(asn1controlOid);
    CMCControlObject.CMCControlObjectBuilder resultBuilder = CMCControlObject.builder().type(controlOid);
    for (TaggedAttribute controlAttr : controlSequence){
      ASN1ObjectIdentifier attrType = controlAttr.getAttrType();
      if (attrType != null && attrType.equals(controlOid.getOid())){
        resultBuilder
          .bodyPartID(controlAttr.getBodyPartID())
          .value(getRequestControlValue(controlOid, controlAttr.getAttrValues()));
      }
    }
    return resultBuilder.build();
  }

  private static Object getRequestControlValue(CMCControlObjectID controlOid, ASN1Set controlAttrVals)
    throws IOException {
    Object controlValue = getControlValue(controlOid, controlAttrVals);
    if (CMCControlObjectID.regInfo.equals(controlOid) || CMCControlObjectID.responseInfo.equals(controlOid)){
      byte[] dataBytes = (byte[]) controlValue;
      return getbytesOrJsonObject(dataBytes, AdminCMCData.class);
    }
    return controlValue;
  }

  private static Object getbytesOrJsonObject(byte[] regInfoBytes, Class<?> dataClass) {
    try {
      return OBJECT_MAPPER.readValue(regInfoBytes, dataClass);
    } catch (Exception ex){
      return regInfoBytes;
    }
  }

  private static Object getControlValue(CMCControlObjectID controlOid, ASN1Set controlAttrVals)
    throws IOException {

    try {
      if (controlAttrVals.size()==0){
        log.debug("No values - Returning null");
        return null;
      }
      ASN1Encodable firstObject = controlAttrVals.getObjectAt(0);
      if (firstObject == null){
        log.debug("No control value - Returning null");
        return null;
      }

      if (CMCControlObjectID.regInfo.equals(controlOid)
        || CMCControlObjectID.responseInfo.equals(controlOid)
        || CMCControlObjectID.senderNonce.equals(controlOid)
        || CMCControlObjectID.recipientNonce.equals(controlOid)
      ){
        return ASN1OctetString.getInstance(firstObject).getOctets();
      }
      if (CMCControlObjectID.getCert.equals(controlOid)){
        return GetCert.getInstance(firstObject);
      }
      if (CMCControlObjectID.lraPOPWitness.equals(controlOid)){
        return LraPopWitness.getInstance(firstObject);
      }
      if (CMCControlObjectID.revokeRequest.equals(controlOid)){
        return RevokeRequest.getInstance(firstObject);
      }
      if (CMCControlObjectID.statusInfoV2.equals(controlOid)){
        return CMCStatusInfoV2.getInstance(firstObject);
      }
    } catch (Exception ex){
      throw new IOException("Error extracting CMC control value", ex);
    }
    log.debug("Unsupported CMC control message {} - returning null", controlOid);
    return null;
  }

  /**
   * Return the status code value of CMCStatus
   * @param cmcStatus CMCStatus
   * @return integer value
   * @throws Exception On illegal status value content
   */
  public static int getCMCStatusCode(CMCStatus cmcStatus) throws Exception{
    ASN1Integer cmcStatusAsn1Int = (ASN1Integer) cmcStatus.toASN1Primitive();
    return cmcStatusAsn1Int.intPositiveValueExact();
  }

  /**
   * Get the control sequence array from a CMC PKI Response
   * @param pkiResponse CMC PKI Response
   * @return control data sequence in the form of an array of {@link TaggedAttribute}
   */
  public static TaggedAttribute[] getResponseControlSequence(PKIResponse pkiResponse){
    List<TaggedAttribute> attributeList = new ArrayList<>();
    ASN1Sequence controlSequence = pkiResponse.getControlSequence();
    if (controlSequence.size() > 0) {
      Iterator<ASN1Encodable> iterator = controlSequence.iterator();
      while (iterator.hasNext()){
        TaggedAttribute csAttr = TaggedAttribute.getInstance(iterator.next());
        attributeList.add(csAttr);
      }
    }
    return attributeList.toArray(new TaggedAttribute[0]);
  }

  /**
   * Return a list of certificate bytes representing a list of X509 Certificates
   * @param certificateList list of certificates
   * @return list of certificate bytes
   * @throws CertificateEncodingException on certificate encoding errors
   */
  public static List<byte[]> getCertByteList(List<X509Certificate> certificateList) throws CertificateEncodingException {
    List<byte[]> certByteList = new ArrayList<>();
    for (X509Certificate cert: certificateList){
      certByteList.add(cert.getEncoded());
    }
    return certByteList;
  }

  /**
   * Return a list of certificate bytes representing a list of X509 Certificates
   * @param certificateList list of certificates
   * @return list of certificate bytes
   * @throws IOException on certificate encoding errors
   */
  public static List<byte[]> getCerHolderByteList(List<X509CertificateHolder> certificateList) throws IOException {
    List<byte[]> certByteList = new ArrayList<>();
    for (X509CertificateHolder cert: certificateList){
      certByteList.add(cert.getEncoded());
    }
    return certByteList;
  }

  public static CAInformation getCAInformation(CMCResponse cmcResponse) throws IOException {
    final AdminCMCData adminCMCData = getAdminCMCData(cmcResponse);
    return CMCUtils.OBJECT_MAPPER.readValue(adminCMCData.getData(), CAInformation.class);
  }
  public static AdminCMCData getAdminCMCData(CMCResponse cmcResponse) throws IOException {
    final CMCControlObject responseControlObject = getResponseControlObject(cmcResponse, CMCObjectIdentifiers.id_cmc_responseInfo);
    return (AdminCMCData) responseControlObject.getValue();
  }
  public static CMCControlObject getResponseControlObject(CMCResponse cmcResponse, ASN1ObjectIdentifier controlObjOid) throws IOException {
    final TaggedAttribute[] taggedAttributes = CMCUtils.getResponseControlSequence(cmcResponse.getPkiResponse());
    return CMCUtils.getCMCControlObject(controlObjOid, taggedAttributes);
  }

  public static List<BigInteger> getAllSerials(CMCResponse cmcResponse) throws IOException {
    final AdminCMCData adminCMCData = getAdminCMCData(cmcResponse);
    final List<String> serials = CMCUtils.OBJECT_MAPPER.readValue(adminCMCData.getData(), new TypeReference<>() {});
    return serials.stream().map(s -> new BigInteger(s, 16)).collect(Collectors.toList());
  }

  public static List<CertificateData> getCertList(CMCResponse cmcResponse) throws IOException {
    final AdminCMCData adminCMCData = getAdminCMCData(cmcResponse);
    return CMCUtils.OBJECT_MAPPER.readValue(adminCMCData.getData(), new TypeReference<>() {});
  }

  /**
   * Get the value of the signed signingTime attribute from a CMS signed CMC message
   * @param cmsContentInfo CMS content info bytes
   * @return signing time attribute value if present, or null
   * @throws CMSException error parsing CMS data
   */
  public static Date getSigningTime(byte[] cmsContentInfo) throws CMSException {
    return getSigningTime(new CMSSignedData(cmsContentInfo));
  }

  /**
   * Get the value of the signed signingTime attribute from a CMS signed CMC message
   * @param signedData CMS signed data
   * @return signing time attribute value if present, or null
   */
  public static Date getSigningTime(CMSSignedData signedData) {
    final SignerInformation signerInformation = signedData.getSignerInfos().iterator().next();
    final Attribute signingTimeAttr = signerInformation.getSignedAttributes().get(CMSAttributes.signingTime);
    return signingTimeAttr == null
      ? null
      : Time.getInstance(signingTimeAttr.getAttrValues().getObjectAt(0)).getDate();
  }

}
