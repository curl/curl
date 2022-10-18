c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ssl
Help: Try SSL/TLS
Protocols: FTP IMAP POP3 SMTP LDAP
Added: 7.20.0
Category: tls
Example: --ssl pop3://example.com/
See-also: ssl-reqd insecure ciphers
Multi: boolean
---
Warning: this is considered an insecure option. Consider using --ssl-reqd
instead to be sure curl upgrades to a secure connection.

Try to use SSL/TLS for the connection. Reverts to a non-secure connection if
the server does not support SSL/TLS. See also --ftp-ssl-control and --ssl-reqd
for different levels of encryption required.

This option is handled in LDAP since version 7.81.0. It is fully supported
by the OpenLDAP backend and ignored by the generic ldap backend.

Please note that a server may close the connection if the negotiation does
not succeed.

This option was formerly known as --ftp-ssl (Added in 7.11.0). That option
name can still be used but will be removed in a future version.
