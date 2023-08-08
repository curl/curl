# Features -- what curl can do

## curl tool

 - config file support
 - multiple URLs in a single command line
 - range "globbing" support: [0-13], {one,two,three}
 - multiple file upload on a single command line
 - custom maximum transfer rate
 - redirect stderr
 - parallel transfers

## libcurl

 - full URL syntax with no length limit
 - custom maximum download time
 - custom least download speed acceptable
 - custom output result after completion
 - guesses protocol from host name unless specified
 - uses .netrc
 - progress bar with time statistics while downloading
 - "standard" proxy environment variables support
 - compiles on win32 (reported builds on 70+ operating systems)
 - selectable network interface for outgoing traffic
 - IPv6 support on Unix and Windows
 - happy eyeballs dual-stack connects
 - persistent connections
 - SOCKS 4 + 5 support, with or without local name resolving
 - supports user name and password in proxy environment variables
 - operations through HTTP proxy "tunnel" (using CONNECT)
 - replaceable memory functions (malloc, free, realloc, etc)
 - asynchronous name resolving (6)
 - both a push and a pull style interface
 - international domain names (10)

## HTTP

 - HTTP/0.9 responses are optionally accepted
 - HTTP/1.0
 - HTTP/1.1
 - HTTP/2, including multiplexing and server push (5)
 - GET
 - PUT
 - HEAD
 - POST
 - multipart formpost (RFC 1867-style)
 - authentication: Basic, Digest, NTLM (9) and Negotiate (SPNEGO) (3)
   to server and proxy
 - resume (both GET and PUT)
 - follow redirects
 - maximum amount of redirects to follow
 - custom HTTP request
 - cookie get/send fully parsed
 - reads/writes the Netscape cookie file format
 - custom headers (replace/remove internally generated headers)
 - custom user-agent string
 - custom referrer string
 - range
 - proxy authentication
 - time conditions
 - via HTTP proxy, HTTPS proxy or SOCKS proxy
 - retrieve file modification date
 - Content-Encoding support for deflate and gzip
 - "Transfer-Encoding: chunked" support in uploads
 - automatic data compression (11)

## HTTPS (1)

 - (all the HTTP features)
 - HTTP/3 experimental support
 - using client certificates
 - verify server certificate
 - via HTTP proxy, HTTPS proxy or SOCKS proxy
 - select desired encryption
 - select usage of a specific SSL version

## FTP

 - download
 - authentication
 - Kerberos 5 (12)
 - active/passive using PORT, EPRT, PASV or EPSV
 - single file size information (compare to HTTP HEAD)
 - 'type=' URL support
 - dir listing
 - dir listing names-only
 - upload
 - upload append
 - upload via http-proxy as HTTP PUT
 - download resume
 - upload resume
 - custom ftp commands (before and/or after the transfer)
 - simple "range" support
 - via HTTP proxy, HTTPS proxy or SOCKS proxy
 - all operations can be tunneled through proxy
 - customizable to retrieve file modification date
 - no dir depth limit

## FTPS (1)

 - implicit `ftps://` support that use SSL on both connections
 - explicit "AUTH TLS" and "AUTH SSL" usage to "upgrade" plain `ftp://`
   connection to use SSL for both or one of the connections

## SCP (8)

 - both password and public key auth

## SFTP (7)

 - both password and public key auth
 - with custom commands sent before/after the transfer

## TFTP

 - download
 - upload

## TELNET

 - connection negotiation
 - custom telnet options
 - stdin/stdout I/O

## LDAP (2)

 - full LDAP URL support

## DICT

 - extended DICT URL support

## FILE

 - URL support
 - upload
 - resume

## SMB

 - SMBv1 over TCP and SSL
 - download
 - upload
 - authentication with NTLMv1

## SMTP

 - authentication: Plain, Login, CRAM-MD5, Digest-MD5, NTLM (9), Kerberos 5
   (4) and External.
 - send emails
 - mail from support
 - mail size support
 - mail auth support for trusted server-to-server relaying
 - multiple recipients
 - via http-proxy

## SMTPS (1)

 - implicit `smtps://` support
 - explicit "STARTTLS" usage to "upgrade" plain `smtp://` connections to use SSL
 - via http-proxy

## POP3

 - authentication: Clear Text, APOP and SASL
 - SASL based authentication: Plain, Login, CRAM-MD5, Digest-MD5, NTLM (9),
   Kerberos 5 (4) and External.
 - list emails
 - retrieve emails
 - enhanced command support for: CAPA, DELE, TOP, STAT, UIDL and NOOP via
   custom requests
 - via http-proxy

## POP3S (1)

 - implicit `pop3s://` support
 - explicit `STLS` usage to "upgrade" plain `pop3://` connections to use SSL
 - via http-proxy

## IMAP

 - authentication: Clear Text and SASL
 - SASL based authentication: Plain, Login, CRAM-MD5, Digest-MD5, NTLM (9),
   Kerberos 5 (4) and External.
 - list the folders of a mailbox
 - select a mailbox with support for verifying the `UIDVALIDITY`
 - fetch emails with support for specifying the UID and SECTION
 - upload emails via the append command
 - enhanced command support for: EXAMINE, CREATE, DELETE, RENAME, STATUS,
   STORE, COPY and UID via custom requests
 - via http-proxy

## IMAPS (1)

 - implicit `imaps://` support
 - explicit "STARTTLS" usage to "upgrade" plain `imap://` connections to use SSL
 - via http-proxy

## MQTT

 - Subscribe to and publish topics using URL scheme `mqtt://broker/topic`

## Footnotes

  1. requires a TLS library
  2. requires OpenLDAP or WinLDAP
  3. requires a GSS-API implementation (such as Heimdal or MIT Kerberos) or
     SSPI (native Windows)
  4. requires a GSS-API implementation, however, only Windows SSPI is
     currently supported
  5. requires nghttp2
  6. requires c-ares
  7. requires libssh2, libssh or wolfSSH
  8. requires libssh2 or libssh
  9. requires OpenSSL, GnuTLS, mbedTLS, Secure Transport or SSPI
     (native Windows)
  10. requires libidn2 or Windows
  11. requires libz, brotli and/or zstd
  12. requires a GSS-API implementation (such as Heimdal or MIT Kerberos)
