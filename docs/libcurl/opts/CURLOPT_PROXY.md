---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPPROXYTUNNEL (3)
  - CURLOPT_PRE_PROXY (3)
  - CURLOPT_PROXYPORT (3)
  - CURLOPT_PROXYTYPE (3)
---

# NAME

CURLOPT_PROXY - proxy to use

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY, char *proxy);
~~~

# DESCRIPTION

Set the *proxy* to use for transfers with this easy handle. The parameter
should be a char * to a null-terminated string holding the hostname or dotted
numerical IP address. A numerical IPv6 address must be written within
[brackets].

To specify port number in this string, append :[port] to the end of the host
name. The proxy's port number may optionally (but discouraged) be specified
with the separate option CURLOPT_PROXYPORT(3). If not specified, libcurl
defaults to using port 1080 for proxies.

The proxy string may be prefixed with [scheme]:// to specify which kind of
proxy is used.

## http://

HTTP Proxy. Default when no scheme or proxy type is specified.

## https://

HTTPS Proxy. (Added in 7.52.0 for OpenSSL and GnuTLS Since 7.87.0, it
also works for BearSSL, mbedTLS, rustls, Schannel, Secure Transport and
wolfSSL.)

This uses HTTP/1 by default. Setting CURLOPT_PROXYTYPE(3) to
**CURLPROXY_HTTPS2** allows libcurl to negotiate using HTTP/2 with proxy.

## socks4://

SOCKS4 Proxy.

## socks4a://

SOCKS4a Proxy. Proxy resolves URL hostname.

## socks5://

SOCKS5 Proxy.

## socks5h://

SOCKS5 Proxy. Proxy resolves URL hostname.

Without a scheme prefix, CURLOPT_PROXYTYPE(3) can be used to specify
which kind of proxy the string identifies.

When you tell the library to use an HTTP proxy, libcurl transparently converts
operations to HTTP even if you specify an FTP URL etc. This may have an impact
on what other features of the library you can use, such as
CURLOPT_QUOTE(3) and similar FTP specifics that do not work unless you
tunnel through the HTTP proxy. Such tunneling is activated with
CURLOPT_HTTPPROXYTUNNEL(3).

Setting the proxy string to "" (an empty string) explicitly disables the use
of a proxy, even if there is an environment variable set for it.

A proxy host string can also include protocol scheme (http://) and embedded
user + password.

Unix domain sockets are supported for socks proxies since 7.84.0. Set
localhost for the host part. e.g. socks5h://localhost/path/to/socket.sock

The application does not have to keep the string around after setting this
option.

When a proxy is used, the active FTP mode as set with *CUROPT_FTPPORT(3)*,
cannot be used.

# Environment variables

libcurl respects the proxy environment variables named **http_proxy**,
**ftp_proxy**, **sftp_proxy** etc. If set, libcurl uses the specified proxy
for that URL scheme. For an "FTP://" URL, the **ftp_proxy** is
considered. **all_proxy** is used if no protocol specific proxy was set.

If **no_proxy** (or **NO_PROXY**) is set, it is the exact equivalent of
setting the CURLOPT_NOPROXY(3) option.

The CURLOPT_PROXY(3) and CURLOPT_NOPROXY(3) options override environment
variables.

# DEFAULT

Default is NULL, meaning no proxy is used.

When you set a hostname to use, do not assume that there is any particular
single port number used widely for proxies. Specify it!

# PROTOCOLS

All except file://. Note that some protocols do not work well over proxy.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/file.txt");
    curl_easy_setopt(curl, CURLOPT_PROXY, "http://proxy:80");
    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Since 7.14.1 the proxy environment variable names can include the protocol
scheme.

Since 7.21.7 the proxy string supports the socks protocols as "schemes".

Since 7.50.2, unsupported schemes in proxy strings cause libcurl to return
error.

# RETURN VALUE

Returns CURLE_OK if proxies are supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
