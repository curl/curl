c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: login-options
Arg: <options>
Protocols: IMAP LDAP POP3 SMTP
Help: Server login options
Added: 7.34.0
Category: imap pop3 smtp auth
Example: --login-options 'AUTH=*' imap://example.com
See-also: user
Multi: single
---
Specify the login options to use during server authentication.

You can use login options to specify protocol specific options that may be
used during authentication. At present only IMAP, POP3 and SMTP support
login options. For more information about login options please see RFC
2384, RFC 5092 and IETF draft draft-earhart-url-smtp-00.txt
