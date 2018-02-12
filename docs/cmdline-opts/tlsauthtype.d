Long: tlsauthtype
Arg: <type>
Help: TLS authentication type
Added: 7.21.4
---
Set TLS authentication type. Currently, the only supported option is "SRP",
for TLS-SRP (RFC 5054). If --tlsuser and --tlspassword are specified but
--tlsauthtype is not, then this option defaults to "SRP".
