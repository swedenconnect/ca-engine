package se.swedenconnect.ca.cmc.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CMCValidationResult {

  private boolean valid;
  private boolean simpleResponse;
  private CMSSignedData signedData;
  private ASN1ObjectIdentifier contentType;
  private List<X509CertificateHolder> signerCertificatePath;
  private Exception exception;
  private String errorMessage;

}
