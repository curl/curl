---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTPPROXYTUNNEL (3)
  - FETCHOPT_PRE_PROXY (3)
  - FETCHOPT_PROXYPORT (3)
  - FETCHOPT_PROXYTYPE (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_PROXY - proxy to use

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY, char *proxy);
~~~

# DESCRIPTION

Set the *proxy* to use for transfers with this easy handle. The parameter
should be a char * to a null-terminated string holding the hostname or dotted
numerical IP address. A numerical IPv6 address must be written within
[brackets].

To specify port number in this string, append :[port] to the end of the host
name. The proxy's port number may optionally (but discouraged) be specified
with the separate option FETCHOPT_PROXYPORT(3). If not specified, libfetch
defaults to using port 1080 for proxies.

The proxy string may be prefixed with [scheme]:// to specify which kind of
proxy is used.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

The application does not have to keep the string around after setting this
option.

## http://

HTTP Proxy. Default when no scheme or proxy type is specified.

## https://

HTTPS Proxy. (Added in 7.52.0 for OpenSSL and GnuTLS Since 7.87.0, it
also works for BearSSL, mbedTLS, Rustls, Schannel, Secure Transport and
wolfSSL.)

This uses HTTP/1 by default. Setting FETCHOPT_PROXYTYPE(3) to
**FETCHPROXY_HTTPS2** allows libfetch to negotiate using HTTP/2 with proxy.

## socks4://

SOCKS4 Proxy.

## socks4a://

SOCKS4a Proxy. Proxy resolves URL hostname.

## socks5://

SOCKS5 Proxy.

## socks5h://

SOCKS5 Proxy. Proxy resolves URL hostname.

##

Without a scheme prefix, FETCHOPT_PROXYTYPE(3) can be used to specify which
kind of proxy the string identifies.

When you tell the library to use an HTTP proxy, libfetch transparently converts
operations to HTTP even if you specify an FTP URL etc. This may have an impact
on what other features of the library you can use, such as FETCHOPT_QUOTE(3)
and similar FTP specifics that do not work unless you tunnel through the HTTP
proxy. Such tunneling is activated with FETCHOPT_HTTPPROXYTUNNEL(3).

Setting the proxy string to "" (an empty string) explicitly disables the use
of a proxy, even if there is an environment variable set for it.

Unix domain sockets are supported for socks proxies since 7.84.0. Set
localhost for the host part. e.g. socks5h://localhost/path/to/socket.sock

When you set a hostname to use, do not assume that there is any particular
single port number used widely for proxies. Specify it.

When a proxy is used, the active FTP mode as set with *CUROPT_FTPPORT(3)*,
cannot be used.

Doing FTP over an HTTP proxy without FETCHOPT_HTTPPROXYTUNNEL(3) set makes
libfetch do HTTP with an FTP URL over the proxy. For such transfers, common FTP
specific options do not work, for example FETCHOPT_USE_SSL(3).

# Authentication

The proxy can also be specified with its associated credentials like for
ordinary URLs in the style: `scheme://username:password@hostname`

Alternatively, set them using FETCHOPT_PROXYUSERNAME(3) and
FETCHOPT_PROXYPASSWORD(3).

# Environment variables

libfetch respects the proxy environment variables named **http_proxy**,
**ftp_proxy**, **sftp_proxy** etc. If set, libfetch uses the specified proxy
for that URL scheme. For an "FTP://" URL, the **ftp_proxy** is
considered. **all_proxy** is used if no protocol specific proxy was set.

If **no_proxy** (or **NO_PROXY**) is set, it is the exact equivalent of
setting the FETCHOPT_NOPROXY(3) option.

The FETCHOPT_PROXY(3) and FETCHOPT_NOPROXY(3) options override environment
variables.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/file.txt");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "http://proxy:80");
    fetch_easy_perform(fetch);
  }
}
~~~

# HISTORY

Since 7.14.1 the proxy environment variable names can include the protocol
scheme.

Since 7.21.7 the proxy string supports the socks protocols as "schemes".

Since 7.50.2, unsupported schemes in proxy strings cause libfetch to return
error.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
