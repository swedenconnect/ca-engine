package se.swedenconnect.ca.cmc.model.admin.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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
public class CertificateData {
  private byte[] certificate;
  private boolean valid;
  private int revocationReason;
  private long revocationDate;
}
