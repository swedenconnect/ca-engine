![Logo](https://raw.githubusercontent.com/swedenconnect/technical-framework/master/img/sweden-connect.png)

# Certificate Authority (CA) Engine

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.ca/ca-engine/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.ca/ca-engine)

Core components for creating a Certificate Authority (CA) service

---

## Maven

Add this maven dependency to your project

```
<dependency>
    <groupId>se.swedenconnect.ca</groupId>
    <artifactId>ca-engine/artifactId>
    <version>${ca-engine.version}</version>
</dependency>
```

##### API documentation

## Migration from version 1.x

Version 2 major release makes a backwards incompatible change to the implementation of the CRLIssuer interface where the old
DefaultCRLIssuer has been removed and replaced by the new SychronizedCRLIssuer. 

The major change of this release is the support of synchronized CRL issuance in clustered service deployment where multiple
instances of the same CA service can provide a unified CRL experience by sharing synchronized CRL metadata.

The synchronized CRL metadata is now provided by the CRLRevocationDataProvider which before was part of the 
CRLIssuer model. This has now moved into the CARepository who have responsibility for all information that
is shared among multiple service instances.

Implementations of ca-engine version 2.x need to do the following updates:

1) Implement the extended interface of CRLRevocationDataProvider to obtain CRLMetadata
2) Feed this CRLRevocationDataProvider directly to the constructor of the SynchronizedCRLIssuer
3) Use the SynchronizedCRLIssuer implementation of CRLIssuer instead of the old DefaultCRLIssuer.


## Java API

### CA Service
This library provides classes for instantiating Certification Authority services with revocation and repository functionality.

The basic interface for the CA service is the `se.swedenconnect.ca.engine.ca.issuer.CAService` interface.

The core functions of a CA service is implemented by the `se.swedenconnect.ca.engine.ca.issuer.impl.AbstractCAService` class. 
The typical way to implement a CA is to extend this class.

**Example:**
```
/**
 * Basic CA service implementation
 */
public class BasicCAService extends AbstractCAService<DefaultCertificateModelBuilder> {

  private final CertificateIssuer certificateIssuer;
  private CRLIssuer crlIssuer;
  private List<String> crlDistributionPoints;
  private OCSPResponder ocspResponder;
  private X509CertificateHolder ocspResponderCertificate;
  private String ocspResponderUrl;

  /**
   * Constructor.
   *
   * @param privateKey private key of the CA service
   * @param caCertificateChain certificate chain representing this CA with the ca certificate of this CA 
                               being the first certificate
   * @param caRepository repository for storing issued certificates
   * @param issuerModel model for issuing certificates
   * @param crlIssuerModel model for publishing CRL:s
   * @throws NoSuchAlgorithmException algorithm is not supported
   */
  public BasicCAService(final PrivateKey privateKey, final List<X509CertificateHolder> caCertificateChain,
      final CARepository caRepository, final CertificateIssuerModel issuerModel, final CRLIssuerModel crlIssuerModel)
      throws NoSuchAlgorithmException {
      
    super(caCertificateChain, caRepository);

    // Setup service
    this.certificateIssuer = new BasicCertificateIssuer(issuerModel, getCaCertificate().getSubject(), privateKey);
    this.crlDistributionPoints = new ArrayList<>();
    if (crlIssuerModel != null) {
      this.crlIssuer = new DefaultCRLIssuer(crlIssuerModel, privateKey);
      this.crlDistributionPoints = List.of(crlIssuerModel.getDistributionPointUrl());
      publishNewCrl();
    }
  }

  /** {@inheritDoc} */
  @Override 
  public CertificateIssuer getCertificateIssuer() {
    return certificateIssuer;
  }

  /** {@inheritDoc} */
  @Override 
  protected CRLIssuer getCrlIssuer() {
    return crlIssuer;
  }

  /** {@inheritDoc} */
  @Override
  public X509CertificateHolder getOCSPResponderCertificate() {
    return ocspResponderCertificate;
  }

  /** {@inheritDoc} */
  @Override
  public String getCaAlgorithm() {
    return certificateIssuer.getCertificateIssuerModel().getAlgorithm();
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getCrlDpURLs() {
    return crlDistributionPoints;
  }

  /** {@inheritDoc} */
  @Override
  public String getOCSPResponderURL() {
    return ocspResponderUrl;
  }

  /**
   * Set OCSP responder for this CA service.
   *
   * @param ocspResponder ocsp responder implementation
   * @param ocspResponderUrl URL for sending requests to the OCSP responder
   * @param ocspResponderCertificate OCSP responder certificate
   */
  public void setOcspResponder(final OCSPResponder ocspResponder, final String ocspResponderUrl,
      final X509CertificateHolder ocspResponderCertificate) {
    this.ocspResponder = ocspResponder;
    this.ocspResponderUrl = ocspResponderUrl;
    this.ocspResponderCertificate = ocspResponderCertificate;
  }

  /** {@inheritDoc} */
  @Override
  public OCSPResponder getOCSPResponder() {
    return ocspResponder;
  }

  /** {@inheritDoc} */
  @Override
  protected DefaultCertificateModelBuilder getBaseCertificateModelBuilder(final CertNameModel subject,
      final PublicKey publicKey, final X509CertificateHolder issuerCertificate, 
      final CertificateIssuerModel certificateIssuerModel)
      throws CertificateIssuanceException {
      
    DefaultCertificateModelBuilder certModelBuilder = DefaultCertificateModelBuilder.getInstance(
        publicKey, getCaCertificate(), certificateIssuerModel);
    certModelBuilder
      .subject(subject)
      .includeAki(true)
      .includeSki(true)
      .basicConstraints(new BasicConstraintsModel(false, true))
      .crlDistributionPoints(crlDistributionPoints.isEmpty() ? null : crlDistributionPoints)
      .ocspServiceUrl(ocspResponder != null ? ocspResponderUrl : null);
    return certModelBuilder;
  }
```

### CARepository

The CARepository is responsible for storing as well as adding, revoking or changing status of issued certificates

This library does not implement a CA repository but provides an interface for such repository 
(`se.swedenconnect.ca.engine.ca.repository.CARepository`).

This interface is designed to match the JPA API for database storage, but could as easily be implemented by a file-based repository.


#### multiple server deployment

As of version 1.3.0 this library CARepository API supports running a CA services on multiple servers each providing a unified
service with common certificate storage and revocation services.

Synchronization of CA repository via a common database has been supported from the start. From 1.3.0 the revocation handling
has been upgraded to issue CRL:s from a common CRL metadata source, sharing and synchronizing information about current
CRL number and issue dates, ensuring that all collaborating servers will provide compatible revocation data at all times.

For this purpose the old "DefaultCRLIssuer" has been deprecated and replaced by the SynchronizedCRLIssuer class.

-----

Copyright &copy; 2021-2023, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).



