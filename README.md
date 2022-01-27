# ca-engine
Library for an Open Source Certificate Authority

This library provides classes for instantiating Certification Authority services with revocation and repository functionality

The basic interface for the CA service is the se.swedenconnect.ca.engine.ca.issuer.CAService interface

The core functions of a CA service is implemented by teh se.swedenconnect.ca.engine.ca.issuer.impl.AbstractCAService class.

The typical way to implement a CA is to extend the AbstractCAService class. Instantiation of this calss requires an implementation of the CARepository interface:

The CARepository interface is responsible for storing as well as adding, revoking or changing status of issued certificates
