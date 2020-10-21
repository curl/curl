Long: noproxy
Arg: <no-proxy-list>
Help: List of hosts which do not use proxy
Added: 7.19.4
Category: proxy
---
Comma-separated list of hosts which do not use a proxy, if one is specified.
The only wildcard is a single * character, which matches all hosts, and
effectively disables the proxy. Each name in this list is matched as either
a domain which contains the hostname, or the hostname itself. For example,
local.com would match local.com, local.com:80, and www.local.com, but not
www.notlocal.com.

Since 7.53.0, This option overrides the environment variables that disable the
proxy. If there's an environment variable disabling a proxy, you can set
noproxy list to \&"" to override it.
