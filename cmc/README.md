# CMC API for Certification Authority integration
____

This is an implementation of a CMC API for the CA engine with a narrowed scope to provide the essential functions of the CA via an open restful API.

This CMC implementation supports two classes of requests:

- Requests from an authorized RA (issue, revoke and get certificate)
- Requests for additional administrative operations

The main difference between these classes of requests is that the request from an authorized RA relies purely on standard CMC request and response data defined in RFC 5272 while requests for additional administrative operations makes use of custom request and response data objects defined for this implementation profile.

## Response and request syntax
### Generic request and response syntax

This implementation of CMC is based on full PKI requests and full PKI responses only. All requests and responses have the form of CMS signatures carrying a CMC request or response data according to RFC 5272.

The PKIData structure of requests only contains a controlSequence for control attributes and optionally a reqSequence for any certificate requests.

The PKIResponse structure of responses only contains a controlSequence

the cmcSequence and the otherMsgSequence in both requests and responses are always empty.

The following control attributes are used in requests:

Control attribute | Usage | Presence
---|---|---
senderNonce  | A unique byte array value  | SHALL be present in all requests
regInfo  | Carry implementation specific data for each request type  | Conditional on request type
getCert  | Used only in requests to get a specific certificate  | SHALL be present in getCert requests and SHALL NOT be present in any other request
lraPOPWitness  | Used with CRMF certificate requests  |  SHALL be present when CRMF certificate request format is used
revokeRequest  | Used only in requests to revoke a certificate  | SHALL be present in revoke requests and SHALL NOT be present in any other request


The following control attributes are used in responses:

Control attribute | Usage | Presence
---|---|---
recipientNonce  | The nonce value of the corresponding request  | SHALL be present in all responses
responseInfo  | Carry implementation specific data for each request type  | Conditional on request type
statusInfoV2  | Status information of the response  | SHALL be present in all responses

All control attributes above are defined in RFC 5272.


### Requests from authorized RA

Standard requests from an authorized RA is limited to the following functions:

- Certificate requests
- Certificate revocation
- Obtaining a specific certificate from the CA database

The reason for this set of functions is that the scope of this implementation is limited to a specific use case where the RA acts as the exclusive entity that is authorized to request or revoke certificates on behalf of certificate subjects. The certificate subject has no direct contact with the CA in this scenario. As such we eliminate all need for a state machine and callback scenarios with multiple entities where for example one entity requests the certificate and another entity approves the certificate or similar. This reduces the protocol to a simple request/response protocol where the result is delivered directly as a response to any supported request.

#### Certificate requests

Certificate requests makes use of one of the following request formats:

- PKCS#10
- CRMF

The PKCS#10 format MAY be used when the private key of the certificate subject is available to sign the certificate request as part of a POP process (Proof Of Possession). This can be achieved in several ways, for example where the actual subject provides a signed PKCS#10 to the RA or where the RA generates the key on behalf of the subject and therefore has access to the key to sign the PKCS#10 request.

In all other cases where the RA can't provide a PKCS#10 request signed by the certificate subject's private key, the RA must assert to the certificate subjects POP of the private key by other means and assert this through the lraPOPWitness control attribute. In these cases, the PKCS#10 request format can't be used and therefore the Certificate Request Message Format (CRMF) must be used.

Responses to a successful certificate request is provided in a signed PKIResponse object. The certificate that was issued, if any, is provided among the CMS certificates as defined in RFC 5272.

#### Revocation requests

Revocation requests make use of the revokeRequest control attribute, specifying the issuer name, certificate serial number of the certificate to revoke, reason code and revocation date.

Successful revocation status is delivered in the response using the statusInfoV2 control attribute.

#### Get cert requests

The GetCert request makes use of the getCert control attribute to specify the issuer and the certificate serial number of the certificate to return. Returned certificate is included in the response exactly in the same way as when certificates are issued. i.e., in the set of certificates in the CMS SingedData structure.

### Request for administrative operations

All requests for administrative operations make use of the regInfo control attribute to hold custom request data and uses the responseInfo control attribute to return data in responses related to these custom requests.

The following administrative operations are currently supported:

- Get information about the target CA
- List all certificate serial numbers
- Get Certificates from the CA repository

All admin service requests provide request data as a JSON string. This JSON string is a JSON serialization of the class se.swedenconnect.ca.cmc.model.admin.AdminCMCData

AdminCMCData holds two data parameters:

```
/** Type of admin request */
private AdminRequestType adminRequestType;
/** Admin request/response data */
private String data;

```

The data string holds another JSON string that contains the JSON serialization of the data object associated with the specified AdminRequestType declaration.

The following table illustrate what data objects that are passed as request and response database

AdminRequestType | Request data | Response data
---|---|---
caInfo  |  absent |  se.swedenconnect.ca.cmc.model.admin.response.CAInformation
listCerts  |  se.swedenconnect.ca.cmc.model.admin.request.ListCerts | List&lt;se.swedenconnect.ca.cmc.model.admin.response.CertificateData>
allCertSerials  | absent  | List&lt;String> (Serialnumbers as hex strings)


## CMC API

This CMC API integration library provides java classes that can be used by both the client and the CA to implement this API.

### CA integration

A API for the CA is implemented using the interface class se.swedenconnect.ca.cmc.api.CMCCaApi

This interface is implemented by the AbstractCMCCaApi and by the AbstractAdminCMCCaApi classes where AbstractCMCCaApi holds basic functions that should be valid for any implementation and where AbstractCMCCaApi adds a typical implementation of all custom admin functions. Finally there is a complete default implementation. The class DefaultCMCCaApi. The complete implementation must also provide functions for generating the final certificate content of any issued certificates.

The CMCCaApi has one function:
> CMCResponse processRequest (CMCRequest cmcRequest)

This function takes a CMCRequest as input and feeds that into the CA service and then returns the result of that operation in the form of a CMCResponse.


The DefaultCMCCaApi can be instantiated as follows:

```
CAService ca = getCAService(); //provide an implementation of the CA service interface
ContentSigner contentSigner = getContentSigner(); // Provide a CMS Content signer
List<X509Certificate> cmsSignerCerts = getResponseSignerCerts(); // Provide the CMS signer certificates
X509Certificate trustedClientCert = getTrustedClientCert(); // Provide a trusted client CMS signer certificate

CMCResponseFactory cmcResponseFactory = new CMCResponseFactory(cmsSignerCerts, contentSigner);
CMCRequestParser cmcRequestParser = new CMCRequestParser(new DefaultCMCValidator(trustedClientCert),
  new DefaultCMCReplayChecker());
CMCCaApi cmcCaApi = new DefaultCMCCaApi(ca, cmcRequestParser, cmcResponseFactory);
```

All requests to the CA is then handled by processing incoming CMC requests and returning the resulting CMC response by executing the function as follows:

CMCResponse response = cmcCaApi.processRequest(cmcRequest)

### Client integration

The client which may be an RA or a CA admin service, implements functioins to generate CMC Requests and to parse the CMCResponses returned from the CA.

CMCReqeusts are created by an object of the se.swedenconnect.ca.cmc.api.CMCReqeustFactory class which may be instantiated as a Bean in a Spring application.

CMCResponses are parsed by an object of the se.swedenconnect.ca.cmc.api.CMCResponseParser class, which also can be instantiated as a Bean.

The following illustrates typical instantiations of these classes:

```
ContentSigner contentSigner = getContentSigner(); // Provide a CMS Content signer for the client
List<X509Certificate> clientSignerCerts = getClientSignerCerts(); // Provide the CMS signer certificates
X509Certificate caSignerCert = getCaSignerCert(); // Provide the trusted CA signer certificate
PublicKey caPublicKey = getCAPublicKey(); // Provide the public key of the CA

CMCRequestFactory cmcRequestFactory = new CMCRequestFactory(clientSignerCerts, contentSigner);
CMCResponseParser cmcResponseParser = new CMCResponseParser(new DefaultCMCValidator(caSignerCert, caPublicKey);

```

A CMC request is then created by providing a CMCRequestModel as input to the cmcRequestFactory as follows:

> CMCRequest cmcRequest = cmcRequestFactory.getCMCRequest(requestModel);

Four different implementations of CMCRequestModel are provided:

- CMCCertificateRequestModel
- CMCRevokeRequestModel
- CMCGetCertRequestModel
- CMCAdminRequestModel
