Long: tlsauthtype
Arg: <type>
Help: TLS authentication type
Added: 7.21.4
Category: tls auth
Example: --tlsauthtype SRP $URL
---
Set TLS authentication type. Currently, the only supported option is "SRP",
for TLS-SRP (RFC 5054). If --tlsuser and --tlspassword are specified but
--tlsauthtype is not, then this option defaults to "SRP".  This option works
only if the underlying libcurl is built with TLS-SRP support, which requires
OpenSSL or GnuTLS with TLS-SRP support.
