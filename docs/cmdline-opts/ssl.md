---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ssl
Help: Try enabling TLS
Protocols: FTP IMAP POP3 SMTP LDAP
Added: 7.20.0
Category: tls imap pop3 smtp ldap
Multi: boolean
See-also:
  - ssl-reqd
  - insecure
  - ciphers
Example:
  - --ssl pop3://example.com/
---

# `--ssl`

Warning: this is considered an insecure option. Consider using --ssl-reqd
instead to be sure curl upgrades to a secure connection.

Try to use SSL/TLS for the connection - often referred to as STARTTLS or STLS
because of the involved commands. Reverts to a non-secure connection if the
server does not support SSL/TLS. See also --ftp-ssl-control and --ssl-reqd for
different levels of encryption required.

This option is handled in LDAP (added in 7.81.0). It is fully supported by the
OpenLDAP backend and ignored by the generic ldap backend.

Please note that a server may close the connection if the negotiation does
not succeed.

This option was formerly known as --ftp-ssl (added in 7.11.0). That option
name can still be used but might be removed in a future version.
