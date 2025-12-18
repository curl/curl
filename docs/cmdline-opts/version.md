---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: version
Short: V
Help: Show version number and quit
Category: important curl
Added: 4.0
Multi: custom
See-also:
  - help
  - manual
Example:
  - --version
---

# `--version`

Display information about curl and the libcurl version it uses.

The first line includes the full version of curl, libcurl and other 3rd party
libraries linked with the executable.

This line may contain one or more TLS libraries. curl can be built to support
more than one TLS library which then makes curl - at start-up - select which
particular backend to use for this invocation.

If curl supports more than one TLS library like this, the ones that are *not*
selected by default are listed within parentheses. Thus, if you do not specify
which backend to use (with the `CURL_SSL_BACKEND` environment variable) the
one listed without parentheses is used. Such builds also have `MultiSSL` set as
a feature.

The second line (starts with `Release-Date:`) shows the release date.

The third line (starts with `Protocols:`) shows all protocols that libcurl
reports to support.

The fourth line (starts with `Features:`) shows specific features libcurl
reports to offer. Available features include:

## `alt-svc`
Support for the Alt-Svc: header is provided.

## `AsynchDNS`
This curl uses asynchronous name resolves. Asynchronous name resolves can be
done using either the c-ares or the threaded resolver backends.

## `brotli`
Support for automatic brotli compression over HTTP(S).

## `CharConv`
curl was built with support for character set conversions (like EBCDIC)

## `Debug`
This curl uses a libcurl built with Debug. This enables more error-tracking
and memory debugging etc. For curl-developers only.

## `ECH`
ECH support is present.

## `gsasl`
The built-in SASL authentication includes extensions to support SCRAM because
libcurl was built with libgsasl.

## `GSS-API`
GSS-API is supported.

## `HSTS`
HSTS support is present.

## `HTTP2`
HTTP/2 support has been built-in.

## `HTTP3`
HTTP/3 support has been built-in.

## `HTTPS-proxy`
This curl is built to support HTTPS proxy.

## `IDN`
This curl supports IDN - international domain names.

## `IPv6`
You can use IPv6 with this.

## `Kerberos`
Kerberos V5 authentication is supported.

## `Largefile`
This curl supports transfers of large files, files larger than 2GB.

## `libz`
Automatic decompression (via gzip, deflate) of compressed files over HTTP is
supported.

## `MultiSSL`
This curl supports multiple TLS backends.

## `NTLM`
NTLM authentication is supported.

## `NTLM_WB`
NTLM delegation to winbind helper is supported.
This feature was removed from curl in 8.8.0.

## `PSL`
PSL is short for Public Suffix List and means that this curl has been built
with knowledge about "public suffixes".

## `SPNEGO`
SPNEGO authentication is supported.

## `SSL`
SSL versions of various protocols are supported, such as HTTPS, FTPS, POP3S
and so on.

## `SSLS-EXPORT`
This build supports TLS session export/import, like with the --ssl-sessions.

## `SSPI`
SSPI is supported.

## `TLS-SRP`
SRP (Secure Remote Password) authentication is supported for TLS.

## `TrackMemory`
Debug memory tracking is supported.

## `Unicode`
Unicode support on Windows.

## `UnixSockets`
Unix sockets support is provided.

## `zstd`
Automatic decompression (via zstd) of compressed files over HTTP is supported.
