Long: ssl
Help: Try SSL/TLS
Protocols: FTP IMAP POP3 SMTP
Added: 7.20.0
Category: tls
Example: --ssl pop3://example.com/
---
Try to use SSL/TLS for the connection.  Reverts to a non-secure connection if
the server does not support SSL/TLS.  See also --ftp-ssl-control and --ssl-reqd
for different levels of encryption required.

This option was formerly known as --ftp-ssl (Added in 7.11.0). That option
name can still be used but will be removed in a future version.
