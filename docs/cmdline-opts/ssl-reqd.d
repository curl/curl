Long: ssl-reqd
Help: Require SSL/TLS
Protocols: FTP IMAP POP3 SMTP LDAP
Added: 7.20.0
Category: tls
Example: --ssl-reqd ftp://example.com
See-also: ssl insecure
---
Require SSL/TLS for the connection. Terminates the connection if the server
does not support SSL/TLS.

This option is handled in LDAP since version 7.81.0. It is fully supported
by the openldap backend and rejected by the generic ldap backend if explicit
TLS is required.

This option was formerly known as --ftp-ssl-reqd.
