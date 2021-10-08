package se.swedenconnect.ca.cmc.model.admin.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CAInformation {

  private int certificateCount;
  private int validCertificateCount;
  List<byte[]> certificateChain;
  byte[] ocspCertificate;

}
