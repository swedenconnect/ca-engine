/*
 * Copyright (c) 2021-2022. Agency for Digital Government (DIGG)
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
package se.swedenconnect.ca.engine.components;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import lombok.AllArgsConstructor;
import lombok.Getter;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.data.TestCa;
import se.swedenconnect.ca.engine.data.TestData;

/**
 * Utility function for test
 *
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class TestUtils {

  public static X509Certificate getCertificate(byte[] certBytes) throws CertificateException, IOException {
    try (InputStream inStream = new ByteArrayInputStream(certBytes)) {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(inStream);
    }
  }

  public static List<X509Certificate> getChain(byte[] certificate, TestCa testCa)
      throws CertificateException, IOException {
    TestCAProvider caProvider = TestData.getTestCAs().get(testCa);
    List<X509Certificate> chain = new ArrayList<>();
    chain.add(getCertificate(certificate));
    chain.add(getCertificate(caProvider.getCa().getCaCertificate().getEncoded()));
    chain.add(getCertificate(caProvider.getRootCA().getCaCertificate().getEncoded()));
    return chain;
  }

  public static KeyPair generateRSAKeyPair(int bits)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    return generateKeyPair(KeyType.RSA, bits);
  }

  public static KeyPair generateECKeyPair(NistCurve curve)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    return generateKeyPair(KeyType.EC, curve);
  }

  public static KeyPair generateKeyPair(KeyType algorithm, Object spec) throws NoSuchAlgorithmException,
      InvalidAlgorithmParameterException {
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

  public enum KeyType {
    RSA, EC, ECDSA;
  }

  @Getter
  @AllArgsConstructor
  public enum NistCurve {
    P521("P-521", SECObjectIdentifiers.secp521r1), P384("P-384", SECObjectIdentifiers.secp384r1), P256("P-256",
        SECObjectIdentifiers.secp256r1), P224("P-224",
            SECObjectIdentifiers.secp224r1), P192("P-192", SECObjectIdentifiers.secp192r1);

    String curveName;
    ASN1ObjectIdentifier curveOid;
  }

}
