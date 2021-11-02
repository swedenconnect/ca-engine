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

package se.swedenconnect.ca.cmc.auth.impl;

import lombok.Setter;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.asn1.cmc.TaggedRequest;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import se.swedenconnect.ca.cmc.api.data.CMCControlObject;
import se.swedenconnect.ca.cmc.auth.AuthorizedCmcOperation;
import se.swedenconnect.ca.cmc.auth.CMCAuthorizationException;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.auth.CMCValidationException;

import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Provides a default CMC validator that validates the CMC signature based on a set of trusted certificates.
 * This validator requires the CMC to be signed by a single certificate.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultCMCValidator extends AbstractCMCValidator{

  private final List<X509CertificateHolder> trustedCMCSigners;
  @Setter private Map<X509CertificateHolder, List<AuthorizedCmcOperation>> clientAuthorizationMap;

  /**
   * Constructor for a default CMC Signature validator
   * @param trustedCMCSigners trusted CMC signer certificates
   * @throws CertificateEncodingException on errors parsing the provided certificates
   */
  public DefaultCMCValidator(X509Certificate... trustedCMCSigners) throws CertificateEncodingException {
    this.trustedCMCSigners = new ArrayList();
    for (X509Certificate cert : trustedCMCSigners) {
      this.trustedCMCSigners.add(new JcaX509CertificateHolder(cert));
    }
  }

  /**
   * Constructor for a default CMC Signature validator
   * @param trustedCMCSigners trusted CMC signer certificates
   */
  public DefaultCMCValidator(X509CertificateHolder... trustedCMCSigners) {
    this.trustedCMCSigners = Arrays.asList(trustedCMCSigners);
  }

  /** {@inheritDoc} */
  @Override protected List<X509CertificateHolder> verifyCMSSignature(CMSSignedData cmsSignedData)
    throws CMCValidationException {
    try {
      Collection<X509CertificateHolder> certsInCMS = cmsSignedData.getCertificates().getMatches(null);
      X509CertificateHolder trustedSignerCert = getTrustedSignerCert(certsInCMS);
      SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder().build(trustedSignerCert);
      SignerInformation signerInformation = cmsSignedData.getSignerInfos().iterator().next();
      final boolean verify = signerInformation.verify(signerInformationVerifier);
      if (!verify) {
        throw new RuntimeException("CMC Signature validation failed");
      }
      return Arrays.asList(trustedSignerCert);
    } catch (Exception ex){
      throw new CMCValidationException(ex.getMessage(), ex);
    }
  }

  @Override protected void verifyAuthorization(X509CertificateHolder signer, ASN1ObjectIdentifier contentType, CMSSignedData signedData)
    throws CMCAuthorizationException {
    if (clientAuthorizationMap == null) {
      // No client authorization map is set. Approve authorization
      return;
    }
    if (!CMCObjectIdentifiers.id_cct_PKIData.equals(contentType)){
      // Authorization only applies to CMC requests in this implementation. Approve.
      return;
    }
    final List<AuthorizedCmcOperation> authorizedCmcOperationList = clientAuthorizationMap.get(signer);
    try {
      // Base authorization read must allways be set
      if (!authorizedCmcOperationList.contains(AuthorizedCmcOperation.read)){
        throw new CMCAuthorizationException("CMC client not authorized to access the requested CA service");
      }
      // Check if there is a certificate issuing request present
      PKIData pkiData = PKIData.getInstance(new ASN1InputStream((byte[]) signedData.getSignedContent().getContent()).readObject());
      TaggedRequest[] reqSequence = pkiData.getReqSequence();
      if (reqSequence.length > 0) {
        if (!authorizedCmcOperationList.contains(AuthorizedCmcOperation.issue)){
          throw new CMCAuthorizationException("CMC client not authorized to issue certificates");
        }
      }
      // Check if there is a revoke request present
      final CMCControlObject revokeControlAttribute = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_revokeRequest, pkiData);
      if (revokeControlAttribute != null && revokeControlAttribute.getValue() != null){
        if (!authorizedCmcOperationList.contains(AuthorizedCmcOperation.revoke)){
          throw new CMCAuthorizationException("CMC client not authorized to revoke certificates");
        }
      }
    }
    catch (CMCAuthorizationException authorizationException) {
      throw authorizationException;
    }
    catch (Exception ex) {
      throw new CMCAuthorizationException("Failure to process CMC client authorization check", ex);
    }
  }

  private X509CertificateHolder getTrustedSignerCert(Collection<X509CertificateHolder> certsInCMS) {
    if (trustedCMCSigners == null | trustedCMCSigners.isEmpty()) {
      throw new IllegalArgumentException("This CMC verifier has no trusted CMC signer certificates");
    }
    if (certsInCMS == null || certsInCMS.size() ==0 ){
      throw new IllegalArgumentException("No signature certificates found in CMC signature");
    }
    Iterator<X509CertificateHolder> iterator = certsInCMS.iterator();
    while (iterator.hasNext()) {
      final X509CertificateHolder cmsCert = iterator.next();
      for (X509CertificateHolder trustedCMCSigner : trustedCMCSigners) {
        if (trustedCMCSigner.equals(cmsCert)) {
          return trustedCMCSigner;
        }
      }
    }
    throw new IllegalArgumentException("No trusted certificate found in signed CMC");
  }

}
