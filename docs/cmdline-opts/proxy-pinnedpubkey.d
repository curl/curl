Long: proxy-pinnedpubkey
Arg: <hashes>
Help: FILE/HASHES public key to verify proxy with
Protocols: TLS
Category: proxy tls
Example: --proxy-pinnedpubkey keyfile $URL
Example: --proxy-pinnedpubkey 'sha256//ce118b51897f4452dc' $URL
Added: 7.59.0
See-also: pinnedpubkey proxy
---
Tells curl to use the specified public key file (or hashes) to verify the
proxy. This can be a path to a file which contains a single public key in PEM
or DER format, or any number of base64 encoded sha256 hashes preceded by
'sha256//' and separated by ';'.

When negotiating a TLS or SSL connection, the server sends a certificate
indicating its identity. A public key is extracted from this certificate and
if it does not exactly match the public key provided to this option, curl will
abort the connection before sending or receiving any data.

If this option is used several times, the last one will be used.
