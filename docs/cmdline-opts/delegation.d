Long: delegation
Arg: <LEVEL>
Help: GSS-API delegation permission
Protocols: GSS/kerberos
Category: auth
Example: --delegation "none" $URL
Added: 7.22.0
See-also: insecure ssl
---
Set LEVEL to tell the server what it is allowed to delegate when it
comes to user credentials.
.RS
.IP "none"
Do not allow any delegation.
.IP "policy"
Delegates if and only if the OK-AS-DELEGATE flag is set in the Kerberos
service ticket, which is a matter of realm policy.
.IP "always"
Unconditionally allow the server to delegate.
.RE

If this option is used several times, the last one will be used.
