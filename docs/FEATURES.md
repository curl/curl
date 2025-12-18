<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Features -- what curl can do

## curl tool

 - config file support
 - multiple URLs in a single command line
 - range "globbing" support: [0-13], {one,two,three}
 - multiple file upload on a single command line
 - redirect stderr
 - parallel transfers

## libcurl

 - URL RFC 3986 syntax
 - custom maximum download time
 - custom lowest download speed acceptable
 - custom output result after completion
 - guesses protocol from hostname unless specified
 - supports .netrc
 - progress bar with time statistics while downloading
 - standard proxy environment variables support
 - have run on 101 operating systems and 28 CPU architectures
 - selectable network interface for outgoing traffic
 - IPv6 support on Unix and Windows
 - happy eyeballs dual-stack IPv4 + IPv6 connects
 - persistent connections
 - SOCKS 4 + 5 support, with or without local name resolving
 - *pre-proxy* support, for *proxy chaining*
 - supports username and password in proxy environment variables
 - operations through HTTP proxy "tunnel" (using CONNECT)
 - replaceable memory functions (malloc, free, realloc, etc)
 - asynchronous name resolving
 - both a push and a pull style interface
 - international domain names (IDN)
 - transfer rate limiting
 - stable API and ABI
 - TCP keep alive
 - TCP Fast Open
 - DNS cache (that can be shared between transfers)
 - non-blocking single-threaded parallel transfers
 - Unix domain sockets to server or proxy
 - DNS-over-HTTPS
 - uses non-blocking name resolves
 - selectable name resolver backend

## URL API

 - parses RFC 3986 URLs
 - generates URLs from individual components
 - manages "redirects"

## Header API

 - easy access to HTTP response headers, from all contexts
 - named headers
 - iterate over headers

## TLS

 - selectable TLS backend(s)
 - TLS False Start
 - TLS version control
 - TLS session resumption
 - key pinning
 - mutual authentication
 - Use dedicated CA cert bundle
 - Use OS-provided CA store
 - separate TLS options for HTTPS proxy

## HTTP

 - HTTP/0.9 responses are optionally accepted
 - HTTP/1.0
 - HTTP/1.1
 - HTTP/2, including multiplexing and server push
 - GET
 - PUT
 - HEAD
 - POST
 - multipart formpost (RFC 1867-style)
 - authentication: Basic, Digest, NTLM (9) and Negotiate (SPNEGO)
   to server and proxy
 - resume transfers
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
 - HTTP/2 or HTTP/1.1 to HTTPS proxy
 - retrieve file modification date
 - Content-Encoding support for deflate, gzip, brotli and zstd
 - "Transfer-Encoding: chunked" support in uploads
 - HSTS
 - alt-svc
 - ETags
 - HTTP/1.1 trailers, both sending and getting

## HTTPS

 - HTTP/3
 - using client certificates
 - verify server certificate
 - via HTTP proxy, HTTPS proxy or SOCKS proxy
 - select desired encryption
 - select usage of a specific TLS version
 - ECH

## FTP

 - download
 - authentication
 - Kerberos 5
 - active/passive using PORT, EPRT, PASV or EPSV
 - single file size information (compare to HTTP HEAD)
 - 'type=' URL support
 - directory listing
 - directory listing names-only
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
 - no directory depth limit

## FTPS

 - implicit `ftps://` support that use SSL on both connections
 - explicit "AUTH TLS" and "AUTH SSL" usage to "upgrade" plain `ftp://`
   connection to use SSL for both or one of the connections

## SSH (both SCP and SFTP)

 - selectable SSH backend
 - known hosts support
 - public key fingerprinting
 - both password and public key auth

## SFTP

 - both password and public key auth
 - with custom commands sent before/after the transfer
 - directory listing

## TFTP

 - download
 - upload

## TELNET

 - connection negotiation
 - custom telnet options
 - stdin/stdout I/O

## LDAP

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

 - authentication: Plain, Login, CRAM-MD5, Digest-MD5, NTLM, Kerberos 5 and
   External
 - send emails
 - mail from support
 - mail size support
 - mail auth support for trusted server-to-server relaying
 - multiple recipients
 - via http-proxy

## SMTPS

 - implicit `smtps://` support
 - explicit "STARTTLS" usage to "upgrade" plain `smtp://` connections to use SSL
 - via http-proxy

## POP3

 - authentication: Clear Text, APOP and SASL
 - SASL based authentication: Plain, Login, CRAM-MD5, Digest-MD5, NTLM,
   Kerberos 5 and External
 - list emails
 - retrieve emails
 - enhanced command support for: CAPA, DELE, TOP, STAT, UIDL and NOOP via
   custom requests
 - via http-proxy

## POP3S

 - implicit `pop3s://` support
 - explicit `STLS` usage to "upgrade" plain `pop3://` connections to use SSL
 - via http-proxy

## IMAP

 - authentication: Clear Text and SASL
 - SASL based authentication: Plain, Login, CRAM-MD5, Digest-MD5, NTLM,
   Kerberos 5 and External
 - list the folders of a mailbox
 - select a mailbox with support for verifying the `UIDVALIDITY`
 - fetch emails with support for specifying the UID and SECTION
 - upload emails via the append command
 - enhanced command support for: EXAMINE, CREATE, DELETE, RENAME, STATUS,
   STORE, COPY and UID via custom requests
 - via http-proxy

## IMAPS

 - implicit `imaps://` support
 - explicit "STARTTLS" usage to "upgrade" plain `imap://` connections to use SSL
 - via http-proxy

## MQTT

 - Subscribe to and publish topics using URL scheme `mqtt://broker/topic`
