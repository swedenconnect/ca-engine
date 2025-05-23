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
package se.swedenconnect.ca.engine.revocation.ocsp.impl;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPModel;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPStatusCheckingException;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Abstract implementation of the OCSP responder.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractOCSPResponder implements OCSPResponder {

  /** Configuration data for the OCSP responder */
  @Getter
  private final OCSPModel ocspModel;

  /** Algorithm properties of the OCSP signing algorithm */
  @Getter
  private final CAAlgorithmRegistry.SignatureAlgorithmProperties algorithmProperties;

  /** private signing key */
  private final PkiCredential ocspIssuerCredential;

  /** OCSP responder certificate chain */
  @Getter
  private final List<X509CertificateHolder> responderCertificateCahin;

  /**
   * Constructor for the abstract OCSP responder.
   *
   * @param ocspModel configuration data for the OCSP responder
   * @param ocspIssuerCredential the private key object used to sign OCSP responses
   * @throws NoSuchAlgorithmException unsupported algorithm
   */
  public AbstractOCSPResponder(final PkiCredential ocspIssuerCredential, final OCSPModel ocspModel)
      throws NoSuchAlgorithmException {
    this.ocspIssuerCredential = ocspIssuerCredential;
    this.algorithmProperties = CAAlgorithmRegistry.getAlgorithmProperties(ocspModel.getAlgorithm());
    this.ocspModel = ocspModel;
    try {
      this.responderCertificateCahin = CAUtils.getCertificateHolderList(ocspIssuerCredential.getCertificateChain());
    }
    catch (final CertificateEncodingException e) {
      log.error("The OCSP responder credentials do not contain a valid OCSP signing certificate");
      throw new RuntimeException(e);
    }
    if (this.responderCertificateCahin.isEmpty()) {
      throw new IllegalArgumentException("OCSP certificate chain must not be empty");
    }
  }

  /** {@inheritDoc} */
  @Override
  public OCSPResp handleRequest(final OCSPRequest ocspRequest) throws CertificateRevocationException {

    // Get this update based on offset settings in the OCSP model
    final Date thisUpdate = CertificateIssuer.getOffsetTime(this.ocspModel.getStartOffset());
    // Get next update based on offset settings in the OCSP model, or null if no offset is set
    final Date nextUpdate = this.ocspModel.getExpiryOffset() == null
        ? null
        : CertificateIssuer.getOffsetTime(this.ocspModel.getExpiryOffset());

    // Get the content signer and digest calculator
    final ContentSigner contentSigner;
    try {
      contentSigner = new JcaContentSignerBuilder(this.algorithmProperties.getSigAlgoName()).build(
          this.ocspIssuerCredential.getPrivateKey());
    }
    catch (final OperatorCreationException ex) {
      log.error("Error creating the OCSP response content signer", ex);
      throw new CertificateRevocationException("", ex);
    }

    try {
      // Begin handling the request
      final TBSRequest tbsRequest = ocspRequest.getTbsRequest();

      if (tbsRequest == null) {
        log.debug("No request provided to the OCSP responder");
        throw new CertificateRevocationException("Null request");
      }

      Extension nonce = null;
      final Extensions requestExtensions = tbsRequest.getRequestExtensions();
      if (requestExtensions != null) {
        nonce = requestExtensions.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
      }
      BasicOCSPRespBuilder responseBuilder = this.getResponseBuilder(nonce);

      // Check status of certificate(s)
      try {
        // Prevent DoS attacks by limiting Nonce to max 1K size
        if (nonce != null && nonce.getExtnValue().getOctets().length > 1024) {
          nonce = null;
          throw new OCSPStatusCheckingException("Nonce length exceeds 1K bytes", OCSPResp.MALFORMED_REQUEST);
        }

        // Validate the request
        this.validateRequest(tbsRequest);
        // Process the requests
        final ASN1Sequence requestList = tbsRequest.getRequestList();
        for (int i = 0; i < requestList.size(); i++) {
          final Request request = Request.getInstance(requestList.getObjectAt(i));
          final CertID certID = request.getReqCert();
          this.validateCertID(certID);
          log.debug("Checking OCSP cert status on cert - {}", certID.getSerialNumber().getPositiveValue());
          responseBuilder.addResponse(
              new CertificateID(certID),
              this.getCertStatus(certID.getSerialNumber().getPositiveValue()),
              thisUpdate,
              nextUpdate);
        }
      }
      catch (final OCSPStatusCheckingException ex) {
        log.info("OCSP request rejected - {}", ex.getMessage());
        // There was a problem determining the status of the requested certificate
        final int responseStatus = ex.getResponseStatus();
        // Start over with a new response builder with no status results
        responseBuilder = this.getResponseBuilder(nonce);
        // Return OCSP response with appropriate status
        return new OCSPRespBuilder().build(responseStatus,
            responseBuilder.build(contentSigner, this.getResponderCertChain(), new Date()));
      }

      // Return successful response
      log.debug("OCSP validation success");
      return new OCSPRespBuilder().build(OCSPResp.SUCCESSFUL,
          responseBuilder.build(contentSigner, this.getResponderCertChain(), new Date()));
    }
    catch (final Exception ex) {
      log.error("Error creating the OCSP response object", ex);
      try {
        // Reaching this point classifies as an internal error in the OCSP responder.
        // This point should never be reached unless there is an error in the implementation of this responder
        final BasicOCSPRespBuilder responseBuilder = this.getResponseBuilder(null);
        return new OCSPRespBuilder().build(OCSPRespBuilder.INTERNAL_ERROR,
            responseBuilder.build(contentSigner, this.getResponderCertChain(), new Date()));
      }
      catch (final Exception ex2) {
        // Fatal error. No response could be returned.
        log.error("Error generating OCSP error response", ex);
        throw new CertificateRevocationException("", ex);
      }
    }
  }

  private X509CertificateHolder[] getResponderCertChain() {
    return this.getResponderCertificateCahin().toArray(new X509CertificateHolder[0]);
  }

  private BasicOCSPRespBuilder getResponseBuilder(final Extension nonce)
      throws OCSPException, OperatorCreationException {

    final BasicOCSPRespBuilder responseBuilder = new BasicOCSPRespBuilder(
        this.getResponderCertificateCahin().get(0).getSubjectPublicKeyInfo(),
        new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1));
    if (nonce != null) {
      log.debug("Found nonce in the request. Adding the nonce to the response.");
      responseBuilder.setResponseExtensions(new Extensions(nonce));
    }
    else {
      log.debug("No nonce in the request. Creating response without nonce.");
    }
    return responseBuilder;
  }

  /**
   * Determines the status of a certificate identified by its serial number. If this request fails, an
   * {@link OCSPStatusCheckingException} is thrown that specifies the appropriate response code of the OCSP response.
   *
   * @param certificateSerial serial number of the certificate being checked by the OCSP responder
   * @return the status of the requested certificate
   * @throws OCSPStatusCheckingException on errors handling the request for certificate status leading to an
   *           unsuccessful response and containing the response status that should be applied in the error response
   */
  protected abstract CertificateStatus getCertStatus(final BigInteger certificateSerial)
      throws OCSPStatusCheckingException;

  /**
   * Provides checks to the OCSP request. Extended tests such as signature checks on signed requests can be performed by
   * extending this function.
   *
   * <p>
   * If validation fails, this function must throw an {@link OCSPStatusCheckingException} which must contain the
   * response status used to send an error response
   * </p>
   *
   * @param tbsRequest OCSP request to validate
   * @throws OCSPStatusCheckingException if request validation fails
   */
  protected void validateRequest(final TBSRequest tbsRequest) throws OCSPStatusCheckingException {
    final ASN1Sequence requestList = tbsRequest.getRequestList();
    if (requestList == null || requestList.size() == 0) {
      throw new OCSPStatusCheckingException("OCSP request does not request status for any certificates",
          OCSPResp.MALFORMED_REQUEST);
    }
  }

  /**
   * Validate that the CertID is legitimate and represents a certificate for which this OCSP responder is authorized to
   * provide status information.
   *
   * @param certID the certificate ID
   * @throws OCSPStatusCheckingException if the certificate ID is not valid or this OCSP responder is not authorized
   */
  protected void validateCertID(final CertID certID) throws OCSPStatusCheckingException {

    try {
      final AlgorithmIdentifier hashAlgorithm = certID.getHashAlgorithm();
      final byte[] providedIssuerKeyHash = certID.getIssuerKeyHash().getOctets();
      final byte[] providedIssuerNameHash = certID.getIssuerNameHash().getOctets();
      final BigInteger serialNumber = certID.getSerialNumber().getPositiveValue();
      if (hashAlgorithm == null || providedIssuerKeyHash == null || providedIssuerNameHash == null
          || serialNumber == null) {
        log.debug("Malformed OCSP request - CertID contains illegal data");
        throw new OCSPStatusCheckingException("Illegal certID", OCSPResp.MALFORMED_REQUEST);
      }

      final DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder().build().get(hashAlgorithm);
      final CertificateID calculatedCertificateId =
          new CertificateID(digestCalculator, this.ocspModel.getCertificateIssuerCert(), serialNumber);
      if (Arrays.equals(providedIssuerKeyHash, calculatedCertificateId.getIssuerKeyHash()) &&
          Arrays.equals(providedIssuerNameHash, calculatedCertificateId.getIssuerNameHash())) {
        return;
      }
      log.debug("OCSP request for certificate not handled by this OCSP responder");
      throw new OCSPStatusCheckingException("OCSP request for certificate not handled by this OCSP responder",
          OCSPResp.UNAUTHORIZED);

    }
    catch (final Exception ex) {
      log.debug("Malformed OCSP request - CertID could not be parsed");
      throw new OCSPStatusCheckingException("Error parsing certID", ex, OCSPResp.MALFORMED_REQUEST);
    }
  }

}
