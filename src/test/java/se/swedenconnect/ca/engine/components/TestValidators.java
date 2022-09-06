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

import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.util.encoders.Base64;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import se.swedenconnect.ca.engine.data.TestCa;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.sigval.cert.chain.AbstractPathValidator;
import se.swedenconnect.sigval.cert.chain.impl.CertificatePathValidator;
import se.swedenconnect.sigval.cert.chain.impl.CertificatePathValidatorFactory;
import se.swedenconnect.sigval.cert.chain.impl.CertificateValidityCheckerFactory;
import se.swedenconnect.sigval.cert.chain.impl.StatusCheckingCertificateValidatorImpl;
import se.swedenconnect.sigval.cert.validity.CertificateValidityChecker;
import se.swedenconnect.sigval.cert.validity.crl.CRLCache;
import se.swedenconnect.sigval.cert.validity.crl.impl.CRLCacheImpl;
import se.swedenconnect.sigval.cert.validity.crl.impl.CRLDataLoader;
import se.swedenconnect.sigval.cert.validity.impl.BasicCertificateValidityChecker;
import se.swedenconnect.sigval.cert.validity.ocsp.OCSPCertificateVerifier;
import se.swedenconnect.sigval.cert.validity.ocsp.OCSPDataLoader;

/**
 * Providing certificate validator for certificates issued by a CA provider
 *
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class TestValidators {

  public static CertValidatorComponents getCertificateValidator(TestCAProvider testCAProvider, boolean singleThreaded)
    throws IOException, CertificateException {

    final TestCa caConfig = testCAProvider.getCaConfig();

    File crlCacheDir = new File(System.getProperty("user.dir"), "target/test/crl-cache/" + caConfig.getId());
    CRLCache crlCache = new CRLCacheImpl(crlCacheDir, 0, new TestCRLDataLoader());

    StatusCheckingCertificateValidatorImpl certificateValidator = new StatusCheckingCertificateValidatorImpl(
      crlCache, null, TestUtils.getCertificate(testCAProvider.getRootCA().getCaCertificate().getEncoded())
    );
    certificateValidator.setCertificatePathValidatorFactory(
      new TestCertificatePathValidatorFactory(testCAProvider.getCa(), singleThreaded));
    certificateValidator.setSingleThreaded(singleThreaded);
    return new CertValidatorComponents(certificateValidator, crlCache);
  }

  public static class TestCertificatePathValidatorFactory implements CertificatePathValidatorFactory {
    private final BasicIssuerCAService ca01;
    private final boolean singleThreaded;

    public TestCertificatePathValidatorFactory(BasicIssuerCAService ca01, boolean singleThreaded) {
      this.ca01 = ca01;
      this.singleThreaded = singleThreaded;
    }

    @Override public AbstractPathValidator getPathValidator(X509Certificate targetCert, List<X509Certificate> chain,
      List<TrustAnchor> trustAnchors, CertStore certStore, CRLCache crlCache) {
      CertificatePathValidator pathValidator = new CertificatePathValidator(targetCert, chain, trustAnchors, certStore, crlCache);
      if (singleThreaded) {
        pathValidator.setSingleThreaded(true);
      }
      else {
        pathValidator.setMaxValidationSeconds(150);
      }
      pathValidator.setCertificateValidityCheckerFactory(new TestCertificateValidityCheckerFactory(ca01));
      return pathValidator;
    }
  }

  public static class TestCertificateValidityCheckerFactory implements CertificateValidityCheckerFactory {
    private final BasicIssuerCAService ca01;

    public TestCertificateValidityCheckerFactory(BasicIssuerCAService ca01) {
      this.ca01 = ca01;
    }

    @Override public CertificateValidityChecker getCertificateValidityChecker(X509Certificate certificate, X509Certificate issuer,
      CRLCache crlCache, PropertyChangeListener... propertyChangeListeners) {
      BasicCertificateValidityChecker validityChecker = new BasicCertificateValidityChecker(certificate, issuer, crlCache,
        propertyChangeListeners);
      validityChecker.setSingleThreaded(true);
      validityChecker.getValidityCheckers().stream()
        .filter(vc -> vc instanceof OCSPCertificateVerifier)
        .map(vc -> (OCSPCertificateVerifier) vc)
        .forEach(ocspCertificateVerifier -> ocspCertificateVerifier.setOcspDataLoader(new TestOCSPDataLoader(ca01)));
      return validityChecker;
    }
  }

  public static class TestOCSPDataLoader implements OCSPDataLoader {
    private final BasicIssuerCAService ca01;
    @Getter private String lastResponseB64;
    @Setter private boolean enforceUrlMatch = true;

    public TestOCSPDataLoader(BasicIssuerCAService ca01) {
      this.ca01 = ca01;
    }

    @Override public OCSPResp requestOCSPResponse(String url, OCSPReq ocspReq, int connectTimeout, int readTimeout) throws IOException {
      OCSPResponder ocspResponder = ca01.getOCSPResponder();
      if (ca01.getOCSPResponderURL().equals(url) || !enforceUrlMatch) {
        @SuppressWarnings("resource")
        OCSPResp ocspResp = ocspResponder.handleRequest(
          OCSPRequest.getInstance(new ASN1InputStream(ocspReq.getEncoded()).readObject()));
        lastResponseB64 = Base64.toBase64String(ocspResp.getEncoded());
        return ocspResp;
      }
      throw new IOException("Unable to get OCSP response on requested URL");
    }
  }

  @NoArgsConstructor
  public static class TestCRLDataLoader implements CRLDataLoader {
    @Override public byte[] downloadCrl(String url, int connectTimeout, int readTimeout) throws IOException {
      if (url.startsWith(TestCAProvider.FILE_URL_PREFIX)) {
        String urlEncodedPath = url.substring(TestCAProvider.FILE_URL_PREFIX.length());
        String filePath = URLDecoder.decode(urlEncodedPath, StandardCharsets.UTF_8);
        File crlFile = new File(filePath);
        return FileUtils.readFileToByteArray(crlFile);
      }
      throw new IOException("Illegal file path URL");
    }
  }

}
