package se.swedenconnect.ca.cmc.model.request.admin;

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
public class ListCerts {

  private boolean valid;
  private SortBy sortBy;
  private int pageSize;
  private int pageIndex;

}
