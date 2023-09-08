c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: noproxy
Arg: <no-proxy-list>
Help: List of hosts which do not use proxy
Added: 7.19.4
Category: proxy
Example: --noproxy "www.example" $URL
See-also: proxy
Multi: single
---
Comma-separated list of hosts for which not to use a proxy, if one is
specified. The only wildcard is a single * character, which matches all hosts,
and effectively disables the proxy. Each name in this list is matched as
either a domain which contains the hostname, or the hostname itself. For
example, local.com would match local.com, local.com:80, and www.local.com, but
not www.notlocal.com.

This option overrides the environment variables that disable the proxy
('no_proxy' and 'NO_PROXY') (added in 7.53.0). If there is an environment
variable disabling a proxy, you can set the no proxy list to "" to override
it.

IP addresses specified to this option can be provided using CIDR notation
(added in 7.86.0): an appended slash and number specifies the number of
"network bits" out of the address to use in the comparison. For example
"192.168.0.0/16" would match all addresses starting with "192.168".
