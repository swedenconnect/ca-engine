package se.swedenconnect.ca.cmc.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
@AllArgsConstructor
public enum PEMType {
  certRequest("CERTIFICATE REQUEST"),
  newCertRequest("NEW CERTIFICATE REQUEST"),
  cert("CERTIFICATE"),
  trustedCert("TRUSTED CERTIFICATE"),
  x509Cert("X509 CERTIFICATE"),
  crl("X509 CRL"),
  pkcs7("PKCS7"),
  cms("CMS"),
  attributeCert("ATTRIBUTE CERTIFICATE"),
  ecParams("EC PARAMETERS"),
  publicKey("PUBLIC KEY"),
  rsaPublicKey("RSA PUBLIC KEY"),
  rsaPrivateKey("RSA PRIVATE KEY"),
  dsaPrivateKey("DSA PRIVATE KEY"),
  ecPrivateKey("EC PRIVATE KEY"),
  encryptedPrivateKey("ENCRYPTED PRIVATE KEY"),
  privateKey("PRIVATE KEY");

  private String header;

}
