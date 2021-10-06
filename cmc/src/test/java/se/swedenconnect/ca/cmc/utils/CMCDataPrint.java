package se.swedenconnect.ca.cmc.utils;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmc.*;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.util.encoders.Base64;
import se.swedenconnect.ca.cmc.api.CMCRequest;
import se.swedenconnect.ca.cmc.api.data.CMCControlObjectID;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.CMCRequestType;
import se.swedenconnect.ca.cmc.model.admin.AdminRequestData;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCDataPrint {

  public static String printCMCRequest(CMCRequest cmcRequest, boolean includeFullMessage, boolean includeCertRequest) {

    if (cmcRequest == null) {
      return "Null CMC Request";
    }

    try {
      StringBuilder b = new StringBuilder();
      String cmcBase64 = Base64.toBase64String(cmcRequest.getCmcRequestBytes());
      CMCRequestType cmcRequestType = cmcRequest.getCmcRequestType();
      b.append("CMC request type: ").append(cmcRequestType).append("\n");
      PKIData pkiData = cmcRequest.getPkiData();
      TaggedAttribute[] controlSequence = pkiData.getControlSequence();
      if (controlSequence.length > 0) {
        b.append("CMC Control sequence (size=").append(controlSequence.length).append(")\n");
        for (TaggedAttribute csAttr : controlSequence) {
          CMCControlObjectID controlObjectID = CMCControlObjectID.getControlObjectID(csAttr.getAttrType());
          b.append("  type: ").append(controlObjectID).append("\n");
          printControlValue(cmcRequestType, controlObjectID, csAttr, b);
        }
      }

      switch (cmcRequestType) {

      case issueCert:
        printIssueCert(pkiData, includeCertRequest, b);
        break;
      }

      if (includeFullMessage) {
        b.append("  Full CMC request:\n").append(base64Print(cmcRequest.getCmcRequestBytes(), 120)).append("\n");
      }

      return b.toString();
    } catch (Exception ex) {
      return "Error parsing CMC request: " + ex.toString() + "\n";
    }
  }

  private static void printControlValue(CMCRequestType cmcRequestType, CMCControlObjectID controlObjectID, TaggedAttribute csAttr,
    StringBuilder b) {
    ASN1Set attrValues = csAttr.getAttrValues();
    for (int i = 0; i < attrValues.size(); i++) {
      ASN1Encodable asn1Encodable = attrValues.getObjectAt(i);
      String valueStr = "";
      try {
        switch (controlObjectID) {

        case senderNonce:
        case recipientNonce:
          valueStr = Base64.toBase64String(ASN1OctetString.getInstance(asn1Encodable).getOctets());
          b.append("    value: ").append(valueStr).append("\n");
          break;
        case regInfo:
          byte[] octets = ASN1OctetString.getInstance(asn1Encodable).getOctets();
          switch (cmcRequestType) {
          case issueCert:
            valueStr = new String(octets, StandardCharsets.UTF_8);
            b.append("    value: ").append(valueStr).append("\n");
            break;
          case revoke:
          case getCert:
            valueStr = Base64.toBase64String(octets);
            b.append("    value: ").append(valueStr).append("\n");
            break;
          case admin:
            AdminRequestData adminRequestData = TestUtils.OBJECT_MAPPER.readValue(octets, AdminRequestData.class);
            b.append("    admin-type: ").append(adminRequestData.getAdminRequestType()).append("\n");
            String requestData = adminRequestData.getRequestData();
            if (requestData != null) {
              valueStr = TestUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
                TestUtils.OBJECT_MAPPER.readValue(requestData, Object.class)
              );
              b.append("    request-data:\n").append(valueStr.replaceAll("(?m)^", "      ")).append("\n");
            }
            break;
          }
          break;
        case lraPOPWitness:
          LraPopWitness lraPopWitness = LraPopWitness.getInstance(asn1Encodable);
          BodyPartID[] bodyIds = lraPopWitness.getBodyIds();
          for (BodyPartID bodyPartID : bodyIds) {
            b.append("    POP witness ID: ").append(bodyPartID.getID()).append("\n");
          }
          break;
        case getCert:
          GetCert getCert = GetCert.getInstance(asn1Encodable);
          String issuerName = getCert.getIssuerName().toString();
          String certSerial = getCert.getSerialNumber().toString(16);
          b.append("    cert-serial: ").append(certSerial).append("\n");
          b.append("    issuer: ").append(issuerName).append("\n");
          break;
        case revokeRequest:
          RevokeRequest revokeRequest = RevokeRequest.getInstance(asn1Encodable);
          b.append("    cert-serial: ").append(revokeRequest.getSerialNumber().toString(16)).append("\n");
          b.append("    ").append(revokeRequest.getReason()).append("\n");
          b.append("    date: ").append(revokeRequest.getInvalidityDate().getDate()).append("\n");
          b.append("    issuer: ").append(revokeRequest.getName()).append("\n");
          break;
        case statusInfoV2:
          CMCStatusInfoV2 statusInfoV2 = CMCStatusInfoV2.getInstance(asn1Encodable);
          CMCStatus cmcStatus = statusInfoV2.getcMCStatus();
          DERUTF8String statusString = statusInfoV2.getStatusString();
          b.append("    CMC Status: ").append(CMCUtils.getCMCStatusString(cmcStatus)).append("\n");
          if (statusString != null) {
            b.append("    Status string: ").append(statusString.getString()).append("\n");
          }
          break;
        default:
          b.append("    Encoded control data: ")
            .append(Base64.toBase64String(asn1Encodable.toASN1Primitive().getEncoded(ASN1Encoding.DER)))
            .append("\n");
          break;
        }
      }
      catch (Exception ex) {
        b.append("    value-error: ").append(ex.toString()).append("\n");
        b.append("    value: ").append(valueStr).append("\n");
      }
    }
  }

  private static void printIssueCert(PKIData pkiData, boolean includeCertRequest, StringBuilder b) throws IOException {
    TaggedRequest[] reqSequence = pkiData.getReqSequence();
    for (TaggedRequest taggedRequest : reqSequence) {
      ASN1Encodable taggedRequestValue = taggedRequest.getValue();
      if (taggedRequestValue instanceof TaggedCertificationRequest) {
        TaggedCertificationRequest taggedCertReq = (TaggedCertificationRequest) taggedRequestValue;
        ASN1Sequence taggedCertReqSeq = ASN1Sequence.getInstance(taggedCertReq.toASN1Primitive());
        BodyPartID certReqBodyPartId = BodyPartID.getInstance(taggedCertReqSeq.getObjectAt(0));
        CertificationRequest certificationRequest = CertificationRequest.getInstance(taggedCertReqSeq.getObjectAt(1));
        b.append("  Certificate request: PKCS#10 Certificate Request\n");
        b.append("    Body part ID: ").append(certReqBodyPartId.getID()).append("\n");
        if (includeCertRequest) {
          b.append("    Certificate Request:\n").append(base64Print(certificationRequest.getEncoded(ASN1Encoding.DER), 120)).append("\n");
        }
        return;
      }
      if (taggedRequestValue instanceof CertReqMsg) {
        CertificateRequestMessage certificateRequestMessage = new CertificateRequestMessage((CertReqMsg) taggedRequestValue);
        ASN1Integer certReqId = ((CertReqMsg) taggedRequestValue).getCertReq().getCertReqId();
        BodyPartID certReqBodyPartId = new BodyPartID(certReqId.longValueExact());
        b.append("  Certificate request: CRMF Certificate Request Message\n");
        b.append("    Body part ID: ").append(certReqBodyPartId.getID()).append("\n");
        if (includeCertRequest){
          b.append("    Certificate Request:\n").append(base64Print(certificateRequestMessage.getEncoded(), 120)).append("\n");
        }
        return;
      }
      b.append(" Certificate request: Unknown request type\n");
    }
  }

  private static String base64Print(byte[] data, int width) {
    // Create a String with linebreaks
    String b64String = Base64.toBase64String(data).replaceAll("(.{" + width + "})", "$1\n");
    // Ident string with 6 spaces
    return b64String.replaceAll("(?m)^", "      ");
  }

}
