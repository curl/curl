<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Code defines to disable features and protocols

## `CURL_DISABLE_ALTSVC`

Disable support for Alt-Svc: HTTP headers.

## `CURL_DISABLE_BINDLOCAL`

Disable support for binding the local end of connections.

## `CURL_DISABLE_COOKIES`

Disable support for HTTP cookies.

## `CURL_DISABLE_BASIC_AUTH`

Disable support for the Basic authentication methods.

## `CURL_DISABLE_BEARER_AUTH`

Disable support for the Bearer authentication methods.

## `CURL_DISABLE_DIGEST_AUTH`

Disable support for the Digest authentication methods.

## `CURL_DISABLE_KERBEROS_AUTH`

Disable support for the Kerberos authentication methods.

## `CURL_DISABLE_NEGOTIATE_AUTH`

Disable support for the negotiate authentication methods.

## `CURL_DISABLE_AWS`

Disable **AWS-SIG4** support.

## `CURL_DISABLE_DICT`

Disable the DICT protocol

## `CURL_DISABLE_DOH`

Disable DNS-over-HTTPS

## `CURL_DISABLE_FILE`

Disable the FILE protocol

## `CURL_DISABLE_FORM_API`

Disable the form API

## `CURL_DISABLE_FTP`

Disable the FTP (and FTPS) protocol

## `CURL_DISABLE_GETOPTIONS`

Disable the `curl_easy_options` API calls that lets users get information
about existing options to `curl_easy_setopt`.

## `CURL_DISABLE_GOPHER`

Disable the GOPHER protocol.

## `CURL_DISABLE_HEADERS_API`

Disable the HTTP header API.

## `CURL_DISABLE_HSTS`

Disable the HTTP Strict Transport Security support.

## `CURL_DISABLE_HTTP`

Disable the HTTP(S) protocols. Note that this then also disable HTTP proxy
support.

## `CURL_DISABLE_HTTP_AUTH`

Disable support for all HTTP authentication methods.

## `CURL_DISABLE_IMAP`

Disable the IMAP(S) protocols.

## `CURL_DISABLE_LDAP`

Disable the LDAP(S) protocols.

## `CURL_DISABLE_LDAPS`

Disable the LDAPS protocol.

## `CURL_DISABLE_LIBCURL_OPTION`

Disable the --libcurl option from the curl tool.

## `CURL_DISABLE_MIME`

Disable MIME support.

## `CURL_DISABLE_MQTT`

Disable MQTT support.

## `CURL_DISABLE_NETRC`

Disable the netrc parser.

## `CURL_DISABLE_NTLM`

Disable support for NTLM.

## `CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG`

Disable the auto load config support in the OpenSSL backend.

## `CURL_DISABLE_PARSEDATE`

Disable date parsing

## `CURL_DISABLE_POP3`

Disable the POP3 protocol

## `CURL_DISABLE_PROGRESS_METER`

Disable the built-in progress meter

## `CURL_DISABLE_PROXY`

Disable support for proxies

## `CURL_DISABLE_RTSP`

Disable the RTSP protocol.

## `CURL_DISABLE_SHUFFLE_DNS`

Disable the shuffle DNS feature

## `CURL_DISABLE_SMB`

Disable the SMB(S) protocols

## `CURL_DISABLE_SMTP`

Disable the SMTP(S) protocols

## `CURL_DISABLE_SOCKETPAIR`

Disable the use of `socketpair()` internally to allow waking up and canceling
`curl_multi_poll()`.

## `CURL_DISABLE_TELNET`

Disable the TELNET protocol

## `CURL_DISABLE_TFTP`

Disable the TFTP protocol

## `CURL_DISABLE_VERBOSE_STRINGS`

Disable verbose strings and error messages.
