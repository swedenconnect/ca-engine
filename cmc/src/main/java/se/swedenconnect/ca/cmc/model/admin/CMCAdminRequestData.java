package se.swedenconnect.ca.cmc.model.admin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class CMCAdminRequestData<T extends Object> {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  public String objectToJson() throws JsonProcessingException {
    return OBJECT_MAPPER.writeValueAsString(this);
  }

  public T getInstance(String jsonString) throws JsonProcessingException {
    return  OBJECT_MAPPER.readValue(jsonString, getDataClass());
  }

  protected abstract Class<T> getDataClass();

}
