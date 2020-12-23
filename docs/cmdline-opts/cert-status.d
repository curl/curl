Long: cert-status
Protocols: TLS
Added: 7.41.0
Help: Verify the status of the server certificate
Category: tls
---
Tells curl to verify the status of the server certificate by using the
Certificate Status Request (aka. OCSP stapling) TLS extension.

If this option is enabled and the server sends an invalid (e.g. expired)
response, if the response suggests that the server certificate has been revoked,
or no response at all is received, the verification fails.

This is currently only implemented in the OpenSSL, GnuTLS and NSS backends.
