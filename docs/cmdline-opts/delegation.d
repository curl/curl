Long: delegation
Arg: <LEVEL>
Help: GSS-API delegation permission
Protocols: GSS/kerberos
Category: auth
---
Set LEVEL to tell the server what it is allowed to delegate when it
comes to user credentials.
.RS
.IP "none"
Don't allow any delegation.
.IP "policy"
Delegates if and only if the OK-AS-DELEGATE flag is set in the Kerberos
service ticket, which is a matter of realm policy.
.IP "always"
Unconditionally allow the server to delegate.
.RE
