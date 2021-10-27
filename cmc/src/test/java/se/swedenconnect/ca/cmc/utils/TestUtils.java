/*
 * Copyright (c) 2021. Agency for Digital Government (DIGG)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.swedenconnect.ca.cmc.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import se.swedenconnect.ca.cmc.ca.TestCA;
import se.swedenconnect.ca.cmc.ca.TestCAHolder;
import se.swedenconnect.ca.cmc.ca.TestServices;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility functions for test
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class TestUtils {

  public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
  public static final String ASCII_STR_REGEX = "^([\\w]|[0-9]|[\\s]){1,}$";

  public static X509Certificate getCertificate(byte[] certBytes) throws CertificateException, IOException {
    try (InputStream inStream = new ByteArrayInputStream(certBytes)) {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(inStream);
    }
  }

  public static List<X509Certificate> getChain(byte[] certificate, TestCA testCa) throws CertificateException, IOException {
    TestCAHolder caProvider = TestServices.getTestCAs().get(testCa);
    List<X509Certificate> chain = new ArrayList<>();
    chain.add(getCertificate(certificate));
    chain.add(getCertificate(caProvider.getCscaService().getCaCertificate().getEncoded()));
    return chain;
  }

  public static KeyPair generateRSAKeyPair(int bits) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    return generateKeyPair(KeyType.RSA, bits);
  }

  public static KeyPair generateECKeyPair(NistCurve curve) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    return generateKeyPair(KeyType.EC, curve);
  }

  public static KeyPair generateKeyPair(KeyType algorithm, Object spec) throws NoSuchAlgorithmException,
    InvalidAlgorithmParameterException {
    KeyPair kp;
    KeyPairGenerator generator;
    generator = KeyPairGenerator.getInstance(algorithm.name(), new BouncyCastleProvider());
    if (spec instanceof AlgorithmParameterSpec) {
      generator.initialize((AlgorithmParameterSpec) spec);
      return generator.generateKeyPair();
    }
    if (spec instanceof NistCurve) {
      ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(((NistCurve) spec).getCurveName());
      generator.initialize(parameterSpec);
      return generator.generateKeyPair();
    }
    generator.initialize((int) spec);
    return generator.generateKeyPair();
  }

  public static List<AttributeTypeAndValueModel> getAttributeValues(X500Name subject) {
    List<AttributeTypeAndValueModel> attrTypeAndValModelList = new ArrayList<>();
    ASN1ObjectIdentifier[] attributeTypes = subject.getAttributeTypes();
    for (ASN1ObjectIdentifier attrType : attributeTypes) {
      RDN[] rdNs = subject.getRDNs(attrType);
      for (RDN rdn : rdNs) {
        AttributeTypeAndValue[] typesAndValues = rdn.getTypesAndValues();
        for (AttributeTypeAndValue typeAndVal : typesAndValues) {
          ASN1ObjectIdentifier type = typeAndVal.getType();
          ASN1Encodable value = typeAndVal.getValue();
          attrTypeAndValModelList.add(new AttributeTypeAndValueModel(type, getValue(value)));
        }
      }
    }
    return attrTypeAndValModelList;
  }

  private static Object getValue(ASN1Encodable value) {

    if (value instanceof DERPrintableString) {
      return ((DERPrintableString) value).getString();
    }
    if (value instanceof DERUTF8String) {
      return ((DERUTF8String) value).getString();
    }
    if (value instanceof DERIA5String) {
      return ((DERIA5String) value).getString();
    }
    if (value instanceof ASN1GeneralizedTime) {
      return ((ASN1GeneralizedTime) value).getTimeString().substring(0, 8);
    }
    return value.toString();
  }

  public static String getCn(X509Certificate certificate) throws CertificateEncodingException {
    return getFirstSubjectAttribute(BCStyle.CN, new JcaX509CertificateHolder(certificate));
  }

  private static String getFirstSubjectAttribute(ASN1ObjectIdentifier oid, X509CertificateHolder cert) {
    return IETFUtils.valueToString(cert.getSubject().getRDNs(oid)[0].getFirst().getValue());
  }

  public static String getStringRepresentation(byte[] responseInfoData) {
    if (responseInfoData == null || responseInfoData.length == 0){
      return "";
    }

    String str = new String(responseInfoData, StandardCharsets.UTF_8);
    if (str.matches(ASCII_STR_REGEX)){
      return str;
    }
    return Base64.toBase64String(responseInfoData);
  }

  public enum KeyType {
    RSA, EC, ECDSA;
  }

  @Getter
  @AllArgsConstructor
  public enum NistCurve {
    P521("P-521", SECObjectIdentifiers.secp521r1),
    P384("P-384", SECObjectIdentifiers.secp384r1),
    P256("P-256", SECObjectIdentifiers.secp256r1),
    P224("P-224", SECObjectIdentifiers.secp224r1),
    P192("P-192", SECObjectIdentifiers.secp192r1);

    String curveName;
    ASN1ObjectIdentifier curveOid;
  }

  public static String getPemFormatedObject(byte[] data, PEMType pemType) throws IOException {
    PemObject pemObject = new PemObject(pemType.getHeader(), data);
    StringWriter strWr = new StringWriter();
    PemWriter pemWriter = new PemWriter(strWr);
    pemWriter.writeObject(pemObject);
    pemWriter.close();
    strWr.close();
    PEMParser pp;
    return strWr.toString();
  }



}
