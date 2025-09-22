---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: sasl-authzid
Arg: <identity>
Help: Identity for SASL PLAIN authentication
Protocols: LDAP IMAP POP3 SMTP
Added: 7.66.0
Category: auth
Multi: single
See-also:
  - login-options
Example:
  - --sasl-authzid zid imap://example.com/
---

# `--sasl-authzid`

Use this authorization identity (**authzid**), during SASL PLAIN
authentication, in addition to the authentication identity (**authcid**) as
specified by --user.

If the option is not specified, the server derives the **authzid** from the
**authcid**, but if specified, and depending on the server implementation, it
may be used to access another user's inbox, that the user has been granted
access to, or a shared mailbox for example.
