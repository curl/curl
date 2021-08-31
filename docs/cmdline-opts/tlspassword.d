Long: tlspassword
Arg: <string>
Help: TLS password
Added: 7.21.4
Category: tls auth
Example: --tlspassword pwd --tlsuser user $URL
---
Set password for use with the TLS authentication method specified with
--tlsauthtype. Requires that --tlsuser also be set.

This doesn't work with TLS 1.3.
