/*
 * Copyright 2021-2025 Sweden Connect
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
package se.swedenconnect.ca.engine.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import se.swedenconnect.ca.engine.ca.attribute.AttributeValueEncoder;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.EncodedCertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;

/**
 * Utility functions in support of the CA library.
 */
public class CAUtils {

  /**
   * Private constructor preventing instantiation.
   */
  private CAUtils() {
  }

  /**
   * Internal function to convert {@link X509CertificateHolder} to {@link X509Certificate}.
   *
   * @param cert certificate to convert
   * @return {@link X509Certificate}
   * @throws IOException input data error
   * @throws CertificateException certificate encoding errors
   */
  public static X509Certificate getCert(final X509CertificateHolder cert) throws IOException, CertificateException {
    try (final InputStream inStream = new ByteArrayInputStream(cert.getEncoded())) {
      final CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(inStream);
    }
  }

  /**
   * Get list of certificates
   *
   * @param certificateHolderList list of certificate holder objects
   * @return list of {@link X509Certificate}
   * @throws CertificateException error processing certificate data
   * @throws IOException error processing certificate data
   */
  public static List<X509Certificate> getCertList(final List<X509CertificateHolder> certificateHolderList)
      throws CertificateException, IOException {
    final List<X509Certificate> certificateList = new ArrayList<>();
    for (final X509CertificateHolder certificateHolder : certificateHolderList) {
      certificateList.add(getCert(certificateHolder));
    }
    return certificateList;
  }

  /**
   * Get a list of {@link X509CertificateHolder} certificates from a list of {@link X509Certificate} objects
   *
   * @param certificateList a list of {@link X509Certificate} objects
   * @return a list of {@link X509CertificateHolder} certificates
   * @throws CertificateEncodingException error parsing certificates
   */
  public static List<X509CertificateHolder> getCertificateHolderList(final List<X509Certificate> certificateList)
      throws CertificateEncodingException {
    final List<X509CertificateHolder> certificateHolderList = new ArrayList<>();
    for (final X509Certificate certificate : certificateList) {
      certificateHolderList.add(new JcaX509CertificateHolder(certificate));
    }
    return certificateHolderList;
  }

  /**
   * Utility function creating a X500Name object based on a certificate name model
   *
   * @param nameModel certificate name model holding information about a certificate name
   * @param attributeValueEncoder attribute value encoder
   * @return X500Name object
   * @throws IOException errors creating the X500Name object
   */
  public static X500Name getX500Name(final CertNameModel<?> nameModel,
      final AttributeValueEncoder attributeValueEncoder)
      throws IOException {
    if (nameModel instanceof EncodedCertNameModel) {
      return ((EncodedCertNameModel) nameModel).getNameData();
    }

    final List<List<AttributeTypeAndValueModel>> rdnSequenceData = ((ExplicitCertNameModel) nameModel).getNameData();
    final ASN1EncodableVector rdnSequence = new ASN1EncodableVector();
    for (final List<AttributeTypeAndValueModel> rdnData : rdnSequenceData) {
      if (!rdnData.isEmpty()) {
        final ASN1EncodableVector rdnSet = new ASN1EncodableVector();
        for (final AttributeTypeAndValueModel attrTypeAndValData : rdnData) {
          final ASN1EncodableVector attrTypeAndVal = new ASN1EncodableVector();
          attrTypeAndVal.add(attrTypeAndValData.getAttributeType());
          attrTypeAndVal
              .add(attributeValueEncoder.encode(attrTypeAndValData.getAttributeType(), attrTypeAndValData.getValue()));
          rdnSet.add(new DERSequence(attrTypeAndVal));
        }
        rdnSequence.add(new DERSet(rdnSet));
      }
    }
    return X500Name.getInstance(new DERSequence(rdnSequence));
  }

}
