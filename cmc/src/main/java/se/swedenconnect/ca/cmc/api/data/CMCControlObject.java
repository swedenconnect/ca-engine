package se.swedenconnect.ca.cmc.api.data;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.cmc.BodyPartID;

/**
 * Data class for a CMC control object
 *
 * These are also referred to in CMC as TaggedAttribute in CMC requests and responses
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CMCControlObject {

  BodyPartID bodyPartID;
  CMCControlObjectID type;
  Object value;

}
