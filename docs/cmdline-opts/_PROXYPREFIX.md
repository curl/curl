<!-- Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al. -->
<!-- SPDX-License-Identifier: curl -->
# PROXY PROTOCOL PREFIXES
The proxy string may be specified with a protocol:// prefix to specify
alternative proxy protocols. (Added in 7.21.7)

If no protocol is specified in the proxy string or if the string does not
match a supported one, the proxy is treated as an HTTP proxy.

The supported proxy protocol prefixes are as follows:
## http://
Makes it use it as an HTTP proxy. The default if no scheme prefix is used.
## https://
Makes it treated as an **HTTPS** proxy.
## socks4://
Makes it the equivalent of --socks4
## socks4a://
Makes it the equivalent of --socks4a
## socks5://
Makes it the equivalent of --socks5
## socks5h://
Makes it the equivalent of --socks5-hostname
