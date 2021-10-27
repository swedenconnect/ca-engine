# CMC API for Certification Authority integration
____

This is an implementation of a CMC API for the CA engine with a narrowed scope to provide the essential functions of the CA via an open restful API.

This CMC implementation supports two classes of requests:

- Standard requests from an authorized RA
- Request for additional administrative functions

The main difference between these classes of requests is that the standard requests from an authorized RA relies on standard CMC request and response data, while the additional admin functions makes use of custom request and response data objects.

## Response and reqeust syntax
### Generic request and response sytax

This implementation of CMC is based on full PKI requests and full PKI responses only. All requests and responses have the form of CMS signatures carrying a CMC request or response data accrodring to RFC 5272.

The PKIData structure of requests only contains a controlSequence for control attributes and optionally a reqSequence for any certificate requests.

The PKIResponse structure of responses only contains a controlSequence

the cmcSequence and the otherMsgSequence in both requests and responses are allways empty.

The following control attributes are used in requests:

Control attribute | Usage | Presence
---|---|---
senderNonce  | A unique byte array value  | SHALL be present in all requests
regInfo  | Carry implementation specific data for each request type  | Conditional on request type
getCert  | Used only in requests to get a specific certificate  | SHALL be present in getCert requests and SHALL NOT be present in any other request
lraPOPWitness  | Used with CRMF certificate requests  |  SHALL be present when CRMF certificate request format is used
revokeRequest  | Used only in requests to revoke a certificate  | SHALL be present in revoke requests and SHALL NOT be present in any other request
messageTime  | The time when the request was produced  | SHALL be present in all requests


The following control attributes are used in responses:

Control attribute | Usage | Presence
---|---|---
recipientNonce  | The nonce value of the corresponding request  | SHALL be present in all responses
responseInfo  | Carry implementation specific data for each request type  | Conditional on request type
statusInfoV2  | Status information of the response  | SHALL be present in all responses
messageTime  | The time when the response was produced  | SHALL be present in all responses

All control attributes above are defined in RFC 5272 except for the messageTime attriute. The messageTime attribute is specified as follows:

ASN.1 Object Identifier | ASN.1 Structure of attribute value
---|---
1.2.752.201.6.1  |  GeneralizedTime

This object identifier is defined as follows:

```
id-eleg OBJECT IDENTIFIER ::= {iso(1) member-body(2) se(752) e-legitimationsnamnden(201)}
id-cmc OBJECT IDENTIFIER ::= { id-eleg 6 } -- CMC control attributes RFC 5272
id-cmc-messageTime OBJECT IDENTIFIER ::= {id-cmc 1} -- Message creation time for CMC requests and responses
```


### Standard requests from authrotized RA

Standard requests from an authorized RA is limited to the following functions:

- Certificate requests
- Certificate revocation
- Obtaining a specific certificate from the CA database

The reason for this particular set of functions is that the scope of this implementation is limited to a particular usecase where the RA is authorized to request or revoke certificates on behalf of the certificate subject. In this scenario the CA has no direct contact with the user and the certificate is either issued/revoked directly upon receipt of the request, or fail the request. The CA service will not wait for any outside approval from anyone.

This reduces the protocol to a simple request/response protocol without any state machine except for the implementation of replay protection.


#### Certificate requests

Certificate requests makes use of one of the following request formats:

- PKCS#10
- CRMF

The PKCS#10 format MAY be used when the private key of the certificate subject is available to sign the certificate request as part of a POP process (Proof Of Possession). This can be achieved in several ways that is outside the scope of this implementation. Two such ways are where the actual subject provides a signed PKCS#10 to the RA in a format that is accepted by the RA and passed on to the CA in the CMC, request. Another scenario is where the RA generates the key on behalf of the subject and therefore has access to the key to sign the PKCS#10 request.

In all cases where the RA has no posession of the private key associated with the public key being certified, the CRMF format MUST be used together with the lraPOPWitness control attribute. This attribut MUST contain the BodyPartID of the CRMF request. This attiubte indicates for the CA that the certificate request with the specified ID holds a public key where the RA has verified the certificate subject's proof of possession.
