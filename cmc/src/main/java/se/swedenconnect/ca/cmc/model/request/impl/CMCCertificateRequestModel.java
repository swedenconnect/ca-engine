package se.swedenconnect.ca.cmc.model.request.impl;

import lombok.*;
import org.bouncycastle.operator.ContentSigner;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Model for creating a CMC Certificate request
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public class CMCCertificateRequestModel extends AbstractCMCRequestModel {

  public CMCCertificateRequestModel(CertificateModel certificateModel, String profile,
    ContentSigner cmcSigner, List<X509Certificate> cmcSignerCerts) {
    super(CMCRequestType.issueCert, cmcSigner, cmcSignerCerts, profile.getBytes(StandardCharsets.UTF_8));
    this.certificateModel = certificateModel;
    this.lraPopWitness = true;
  }

  public CMCCertificateRequestModel(CertificateModel certificateModel, String profile,
    ContentSigner cmcSigner, List<X509Certificate> cmcSignerCerts, PrivateKey certReqPrivate, String p10Algorithm) {
    super(CMCRequestType.issueCert, cmcSigner, cmcSignerCerts, profile.getBytes(StandardCharsets.UTF_8));
    this.certificateModel = certificateModel;
    this.certReqPrivate = certReqPrivate;
    this.p10Algorithm = p10Algorithm;
    this.lraPopWitness = false;
  }

  /** Certificate request model */
  private CertificateModel certificateModel;
  /** Private key of the requested certificate used to sign PKCS#10 requests */
  private PrivateKey certReqPrivate;
  /** Algorithm URI identifier for the algorithm used to sign the pkcs10 request */
  private String p10Algorithm;
  /** Boolean to indicate if the requester has verified proof-of-possession of certified private key */
  private boolean lraPopWitness;
}
