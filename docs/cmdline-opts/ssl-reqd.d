Long: ssl-reqd
Help: Require SSL/TLS
Protocols: FTP IMAP POP3 SMTP
Added: 7.20.0
Category: tls
Example: --ssl-reqd ftp://example.com
---
Require SSL/TLS for the connection.  Terminates the connection if the server
does not support SSL/TLS.

This option was formerly known as --ftp-ssl-reqd.
