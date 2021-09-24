package se.swedenconnect.ca.cmc.model.impl;

import lombok.Getter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import se.swedenconnect.ca.cmc.model.CMCRequestType;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * CMC Revocation request model
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public class CMCGetCertRequestModel extends AbstractCMCRequestModel {
  public CMCGetCertRequestModel(BigInteger serialNumber,
    X500Name issuerName, ContentSigner cmcSigner, List<X509Certificate> cmcSignerCerts) {
    super(CMCRequestType.revoke, cmcSigner, cmcSignerCerts);
    this.serialNumber = serialNumber;
    this.issuerName = issuerName;
  }
  private X500Name issuerName;
  private BigInteger serialNumber;
}
