Long: oauth2-bearer
Help: OAuth 2 Bearer Token
Arg: <token>
Protocols: IMAP POP3 SMTP HTTP
Category: auth
Example: --oauth2-bearer "mF_9.B5f-4.1JqM" $URL
Added: 7.33.0
---
Specify the Bearer Token for OAUTH 2.0 server authentication. The Bearer Token
is used in conjunction with the user name which can be specified as part of
the --url or --user options.

The Bearer Token and user name are formatted according to RFC 6750.

If this option is used several times, the last one will be used.
