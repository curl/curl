---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ssl-reqd
Help: Require SSL/TLS
Protocols: FTP IMAP POP3 SMTP LDAP
Added: 7.20.0
Category: tls
Multi: boolean
See-also:
  - ssl
  - insecure
Example:
  - --ssl-reqd ftp://example.com
---

# `--ssl-reqd`

Require SSL/TLS for the connection - often referred to as STARTTLS or STLS
because of the involved commands. Terminates the connection if the transfer
cannot be upgraded to use SSL/TLS.

This option is handled in LDAP (added in 7.81.0). It is fully supported by the
OpenLDAP backend and rejected by the generic ldap backend if explicit TLS is
required.

This option is unnecessary if you use a URL scheme that in itself implies
immediate and implicit use of TLS, like for FTPS, IMAPS, POP3S, SMTPS and
LDAPS. Such a transfer always fails if the TLS handshake does not work.

This option was formerly known as --ftp-ssl-reqd.
