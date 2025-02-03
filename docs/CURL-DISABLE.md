<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: fetch
-->

# Code defines to disable features and protocols

## `FETCH_DISABLE_ALTSVC`

Disable support for Alt-Svc: HTTP headers.

## `FETCH_DISABLE_BINDLOCAL`

Disable support for binding the local end of connections.

## `FETCH_DISABLE_COOKIES`

Disable support for HTTP cookies.

## `FETCH_DISABLE_BASIC_AUTH`

Disable support for the Basic authentication methods.

## `FETCH_DISABLE_BEARER_AUTH`

Disable support for the Bearer authentication methods.

## `FETCH_DISABLE_DIGEST_AUTH`

Disable support for the Digest authentication methods.

## `FETCH_DISABLE_KERBEROS_AUTH`

Disable support for the Kerberos authentication methods.

## `FETCH_DISABLE_NEGOTIATE_AUTH`

Disable support for the negotiate authentication methods.

## `FETCH_DISABLE_AWS`

Disable **aws-sigv4** support.

## `FETCH_DISABLE_CA_SEARCH`

Disable unsafe CA bundle search in PATH on Windows.

## `FETCH_DISABLE_DICT`

Disable the DICT protocol

## `FETCH_DISABLE_DOH`

Disable DNS-over-HTTPS

## `FETCH_DISABLE_FILE`

Disable the FILE protocol

## `FETCH_DISABLE_FORM_API`

Disable the form API

## `FETCH_DISABLE_FTP`

Disable the FTP (and FTPS) protocol

## `FETCH_DISABLE_GETOPTIONS`

Disable the `fetch_easy_options` API calls that lets users get information
about existing options to `fetch_easy_setopt`.

## `FETCH_DISABLE_GOPHER`

Disable the GOPHER protocol.

## `FETCH_DISABLE_HEADERS_API`

Disable the HTTP header API.

## `FETCH_DISABLE_HSTS`

Disable the HTTP Strict Transport Security support.

## `FETCH_DISABLE_HTTP`

Disable the HTTP(S) protocols. Note that this then also disable HTTP proxy
support.

## `FETCH_DISABLE_HTTP_AUTH`

Disable support for all HTTP authentication methods.

## `FETCH_DISABLE_IMAP`

Disable the IMAP(S) protocols.

## `FETCH_DISABLE_LDAP`

Disable the LDAP(S) protocols.

## `FETCH_DISABLE_LDAPS`

Disable the LDAPS protocol.

## `FETCH_DISABLE_LIBFETCH_OPTION`

Disable the --libfetch option from the fetch tool.

## `FETCH_DISABLE_MIME`

Disable MIME support.

## `FETCH_DISABLE_MQTT`

Disable MQTT support.

## `FETCH_DISABLE_NETRC`

Disable the netrc parser.

## `FETCH_DISABLE_NTLM`

Disable support for NTLM.

## `FETCH_DISABLE_OPENSSL_AUTO_LOAD_CONFIG`

Disable the auto load config support in the OpenSSL backend.

## `FETCH_DISABLE_PARSEDATE`

Disable date parsing

## `FETCH_DISABLE_POP3`

Disable the POP3 protocol

## `FETCH_DISABLE_PROGRESS_METER`

Disable the built-in progress meter

## `FETCH_DISABLE_PROXY`

Disable support for proxies

## `FETCH_DISABLE_IPFS`

Disable the IPFS/IPNS protocols. This affects the fetch tool only, where
IPFS/IPNS protocol support is implemented.

## `FETCH_DISABLE_RTSP`

Disable the RTSP protocol.

## `FETCH_DISABLE_SHA512_256`

Disable the SHA-512/256 hash algorithm.

## `FETCH_DISABLE_SHUFFLE_DNS`

Disable the shuffle DNS feature

## `FETCH_DISABLE_SMB`

Disable the SMB(S) protocols

## `FETCH_DISABLE_SMTP`

Disable the SMTP(S) protocols

## `FETCH_DISABLE_SOCKETPAIR`

Disable the use of `socketpair()` internally to allow waking up and canceling
`fetch_multi_poll()`.

## `FETCH_DISABLE_TELNET`

Disable the TELNET protocol

## `FETCH_DISABLE_TFTP`

Disable the TFTP protocol

## `FETCH_DISABLE_VERBOSE_STRINGS`

Disable verbose strings and error messages.

## `FETCH_DISABLE_WEBSOCKETS`

Disable the WebSocket protocols.
