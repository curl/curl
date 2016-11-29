Long: login-options
Arg: <options>
Protocols: IMAP POP3 SMTP
Help: Server login options
Added: 7.34.0
---
Specify the login options to use during server authentication.

You can use the login options to specify protocol specific options that may
be used during authentication. At present only IMAP, POP3 and SMTP support
login options. For more information about the login options please see
RFC 2384, RFC 5092 and IETF draft draft-earhart-url-smtp-00.txt

If this option is used several times, the last one will be used.
