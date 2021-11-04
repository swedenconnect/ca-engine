package se.swedenconnect.ca.cmc.api.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import se.swedenconnect.ca.cmc.api.CMCCertificateModelBuilder;
import se.swedenconnect.ca.cmc.api.CMCRequestFactory;
import se.swedenconnect.ca.cmc.api.CMCResponseParser;
import se.swedenconnect.ca.cmc.api.client.impl.CMCClientHttpConnectorImpl;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.auth.impl.DefaultCMCValidator;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.admin.AdminRequestType;
import se.swedenconnect.ca.cmc.model.admin.request.ListCerts;
import se.swedenconnect.ca.cmc.model.admin.response.CAInformation;
import se.swedenconnect.ca.cmc.model.request.impl.CMCAdminRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCCertificateRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCGetCertRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCRevokeRequestModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.repository.SortBy;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMCClient {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private final CMCRequestFactory cmcRequestFactory;
  private final CMCResponseParser cmcResponseParser;
  private CAInformation cachedCAInformation;
  private Date lastCAInfoRecache;
  private final URL cmcRequestUrl;

  @Setter private int connectTimeout = 1000;
  @Setter private int readTimeout = 5000;
  @Setter private int timeSkew = 60000;
  @Setter private int maxAge = 60000;
  @Setter private int caInfoMaxAge = 600000;
  @Setter private CMCClientHttpConnector cmcClientHttpConnector;

  public CMCClient(String cmcRequestUrl, PrivateKey cmcSigningKey, X509Certificate cmcSigningCert, String algorithm,
    X509Certificate cmcResponseCert, X509Certificate caCertificate)
    throws MalformedURLException, NoSuchAlgorithmException, OperatorCreationException, CertificateEncodingException {
    this.cmcRequestUrl = new URL(cmcRequestUrl);
    ContentSigner contentSigner = new JcaContentSignerBuilder(CAAlgorithmRegistry.getSigAlgoName(algorithm)).build(cmcSigningKey);
    this.cmcRequestFactory = new CMCRequestFactory(List.of(cmcSigningCert), contentSigner);
    this.cmcResponseParser = new CMCResponseParser(new DefaultCMCValidator(cmcResponseCert), caCertificate.getPublicKey());
    this.cmcClientHttpConnector = new CMCClientHttpConnectorImpl();
  }

  public CMCResponse caInfoRequest() throws IOException {

    final CMCRequest cmcRequest = cmcRequestFactory.getCMCRequest(new CMCAdminRequestModel(AdminCMCData.builder()
      .adminRequestType(AdminRequestType.caInfo)
      .build()));

    return getCMCResponse(cmcRequest);
  }

  public CMCResponse allSerialsRequest() throws IOException {
    final CMCRequest cmcRequest = cmcRequestFactory.getCMCRequest(new CMCAdminRequestModel(AdminCMCData.builder()
      .adminRequestType(AdminRequestType.allCertSerials)
      .build()));

    return getCMCResponse(cmcRequest);
  }

  public CMCResponse certIssuerRequest(CertificateModel certificateModel) throws IOException {
    final CMCRequest cmcRequest = cmcRequestFactory.getCMCRequest(new CMCCertificateRequestModel(certificateModel, "crmf"));
    return getCMCResponse(cmcRequest);
  }

  public CMCResponse getCertRequest(BigInteger serialNumber) throws IOException {
    final CAInformation caInformation = getCAInformation(false);
    X509CertificateHolder caIssuerCert = new X509CertificateHolder(caInformation.getCertificateChain().get(0));
    final CMCRequest cmcRequest = cmcRequestFactory.getCMCRequest(new CMCGetCertRequestModel(serialNumber, caIssuerCert.getSubject()));
    return getCMCResponse(cmcRequest);
  }

  public CMCResponse revokeCertificateRequest(BigInteger serialNumber, int reason, Date revocationDate) throws IOException {
    final CAInformation caInformation = getCAInformation(false);
    X509CertificateHolder caIssuerCert = new X509CertificateHolder(caInformation.getCertificateChain().get(0));
    final CMCRequest cmcRequest = cmcRequestFactory.getCMCRequest(new CMCRevokeRequestModel(
      serialNumber,
      reason,
      revocationDate,
      caIssuerCert.getSubject()
    ));
    return getCMCResponse(cmcRequest);
  }

  public CMCResponse listCertificatesRequest(int pageSize, int pageIndex, SortBy sortBy, boolean notRevoked) throws IOException {
    final CMCRequest cmcRequest = cmcRequestFactory.getCMCRequest(new CMCAdminRequestModel(AdminCMCData.builder()
      .adminRequestType(AdminRequestType.listCerts)
      .data(OBJECT_MAPPER.writeValueAsString(ListCerts.builder()
        .pageSize(pageSize)
        .pageIndex(pageIndex)
        .sortBy(sortBy)
        .notRevoked(notRevoked)
        .build()))
      .build()));
    return getCMCResponse(cmcRequest);
  }

  /**
   * Return a certificate model builder prepared for creating certificate models for certificate requests to this CA service via CMC
   *
   * @param subjectPublicKey the public key of the subject
   * @param subject          subject name data
   * @param includeCrlDPs    true to include CRL distribution point URLs in the issued certificate
   * @param includeOcspURL   true to include OCSP URL (if present) in the issued certificate
   * @return certificate model builder
   * @throws IOException errors obtaining the certificate model builder
   */
  public CMCCertificateModelBuilder getCertificateModelBuilder(PublicKey subjectPublicKey, CertNameModel<?> subject,
    boolean includeCrlDPs, boolean includeOcspURL) throws IOException {
    final CAInformation caInformation = getCAInformation(false);
    X509CertificateHolder caIssuerCert = new X509CertificateHolder(caInformation.getCertificateChain().get(0));
    CMCCertificateModelBuilder certModelBuilder = CMCCertificateModelBuilder.getInstance(subjectPublicKey, caIssuerCert,
      caInformation.getCaAlgorithm());

    if (includeCrlDPs) {
      certModelBuilder.crlDistributionPoints(caInformation.getCrlDpURLs());
    }
    if (includeOcspURL) {
      certModelBuilder.ocspServiceUrl(caInformation.getOcspResponserUrl());
    }
    certModelBuilder.subject(subject);
    return certModelBuilder;
  }

  public CAInformation getCAInformation(boolean forceRecache) throws IOException {
    if (!forceRecache) {
      if (this.cachedCAInformation != null && lastCAInfoRecache != null) {
        Date notBefore = new Date(System.currentTimeMillis() - caInfoMaxAge);
        if (lastCAInfoRecache.after(notBefore)) {
          // Re-cache is not forced and current cache is not too old. Use it.
          return cachedCAInformation;
        }
      }
    }
    // Re-cache is required
    cachedCAInformation = CMCResponseExtract.extractCAInformation(caInfoRequest());
    lastCAInfoRecache = new Date();
    return cachedCAInformation;
  }

  private CMCResponse getCMCResponse(CMCRequest cmcRequest) throws IOException {

    CMCHttpResponseData httpResponseData = cmcClientHttpConnector.sendCmcRequest(cmcRequest.getCmcRequestBytes(), cmcRequestUrl, connectTimeout, readTimeout);
    if (httpResponseData.getResponseCode() > 205 || httpResponseData.getException() != null){
      throw new IOException("Http connection to CA failed");
    }
    byte[] cmcResponseBytes = httpResponseData.getData();
    Date notBefore = new Date(System.currentTimeMillis() - maxAge);
    Date notAfter = new Date(System.currentTimeMillis() + timeSkew);
    final Date signingTime;
    try {
      signingTime = CMCUtils.getSigningTime(cmcResponseBytes);
      if (signingTime.before(notBefore)) {
        throw new IOException("CMC Response is to old");
      }
      if (signingTime.after(notAfter)) {
        throw new IOException("CMC Response is predated - possible time skew problem");
      }
    }
    catch (CMSException e) {
      throw new IOException("Error parsing signing time in CMC Response", e);
    }

    CMCResponse cmcResponse = cmcResponseParser.parseCMCresponse(cmcResponseBytes, cmcRequest.getCmcRequestType());
    if (!Arrays.equals(cmcRequest.getNonce(), cmcResponse.getNonce())) {
      throw new IOException("CMC response and request nonce mismatch");
    }
    return cmcResponse;

  }

}
