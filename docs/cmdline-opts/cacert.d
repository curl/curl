Long: cacert
Arg: <CA certificate>
Help: CA certificate to verify peer against
Protocols: TLS
---
Tells curl to use the specified certificate file to verify the peer. The file
may contain multiple CA certificates. The certificate(s) must be in PEM
format. Normally curl is built to use a default file for this, so this option
is typically used to alter that default file.

curl recognizes the environment variable named 'CURL_CA_BUNDLE' if it is
set, and uses the given path as a path to a CA cert bundle. This option
overrides that variable.

The windows version of curl will automatically look for a CA certs file named
\'curl-ca-bundle.crt\', either in the same directory as curl.exe, or in the
Current Working Directory, or in any folder along your PATH.

If curl is built against the NSS SSL library, the NSS PEM PKCS#11 module
(libnsspem.so) needs to be available for this option to work properly.

(iOS and macOS only) If curl is built against Secure Transport, then this
option is supported for backward compatibility with other SSL engines, but it
should not be set. If the option is not set, then curl will use the
certificates in the system and user Keychain to verify the peer, which is the
preferred method of verifying the peer's certificate chain.

If this option is used several times, the last one will be used.
