---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: login-options
Arg: <options>
Protocols: IMAP LDAP POP3 SMTP
Help: Server login options
Added: 7.34.0
Category: imap pop3 smtp auth ldap
Multi: single
See-also:
  - user
Example:
  - --login-options 'AUTH=*' imap://example.com
---

# `--login-options`

Specify the login options to use during server authentication.

You can use login options to specify protocol specific options that may be used
during authentication. At present only IMAP, NTLM, POP3 and SMTP support login
options. For more information about login options please see RFC 2384, RFC 5092
and the IETF draft
https://datatracker.ietf.org/doc/html/draft-earhart-url-smtp-00

Since 8.2.0, IMAP supports the login option `AUTH=+LOGIN`. With this option,
curl uses the plain (not SASL) `LOGIN IMAP` command even if the server
advertises SASL authentication. Care should be taken in using this option, as
it sends your password over the network in plain text. This does not work if
the IMAP server disables the plain `LOGIN` (e.g. to prevent password
snooping).

Since x.x.x, NTLM supports the login option `LOCALHOSTNAME=<workstation>`. With
this option, curl explicitly sets the workstation name in the 3rd step of the
NTLM handshake to the specified value. Old versions of curl transmitted the
client's hostname as workstation name, whereas newer versions hardcode it to
`WORKSTATION`.
