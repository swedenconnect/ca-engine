package se.swedenconnect.ca.engine.utils;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.encoders.Base64;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class TestUtils {

  public static String base64Print(byte[] data) {
    return base64Print(data, 80);
  }
  public static String base64Print(String data) {
    return base64Print(data, 80);
  }
  public static String base64Print(String data, int width) {
    return base64Print(Base64.decode(data), width);
  }

  public static String base64Print(byte[] data, int width) {
    // Create a String with linebreaks
    String b64String = Base64.toBase64String(data).replaceAll("(.{" + width + "})", "$1\n");
    // Ident string with 6 spaces
    return b64String.replaceAll("(?m)^", "      ");
  }


}
