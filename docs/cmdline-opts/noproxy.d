c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: noproxy
Arg: <no-proxy-list>
Help: List of hosts which do not use proxy
Added: 7.19.4
Category: proxy
Example: --noproxy "www.example" $URL
See-also: proxy
---
Comma-separated list of hosts for which not to use a proxy, if one is
specified. The only wildcard is a single * character, which matches all hosts,
and effectively disables the proxy. Each name in this list is matched as
either a domain which contains the hostname, or the hostname itself. For
example, local.com would match local.com, local.com:80, and www.local.com, but
not www.notlocal.com.

Since 7.53.0, This option overrides the environment variables that disable the
proxy ('no_proxy' and 'NO_PROXY'). If there's an environment variable
disabling a proxy, you can set the noproxy list to "" to override it.
