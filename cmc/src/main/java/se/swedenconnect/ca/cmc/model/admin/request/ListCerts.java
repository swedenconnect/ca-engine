package se.swedenconnect.ca.cmc.model.admin.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.swedenconnect.ca.engine.ca.repository.SortBy;

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
