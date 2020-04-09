# v0.2.2 (2020-04-09)

* adapt to x509 0.11.0 API #21

# v0.2.1 (2020-03-12)

* use mirage-crypto instead of nocrypto #20
* reorder arguments for nsupdate to avoid a labelled one at the end #20

# v0.2.0 (2020-02-18)

* support ACME as specified in RFC 8555 (letsencrypt v2 endpoints) #19
* support for the ALPN challenge as well #19

# v0.1.1 (2020-01-27)

* use X509.Signing_request.hostnames, introduced in x509 v0.9.0
* provide a custom log source

# v0.1.0 (2019-11-02)

* Initial release