package se.swedenconnect.ca.cmc.model.request.impl;

import lombok.Getter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

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
public class CMCRevokeRequestModel extends AbstractCMCRequestModel {
  public CMCRevokeRequestModel(BigInteger serialNumber, int reason, Date revocationDate,
    X500Name issuerName) {
    super(CMCRequestType.revoke);
    this.serialNumber = serialNumber;
    this.reason = reason;
    this.revocationDate = revocationDate;
    this.issuerName = issuerName;
  }
  private X500Name issuerName;
  private BigInteger serialNumber;
  private int reason;
  private Date revocationDate;
}
