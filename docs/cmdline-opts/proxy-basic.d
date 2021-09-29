Long: proxy-basic
Help: Use Basic authentication on the proxy
See-also: proxy proxy-anyauth proxy-digest
Category: proxy auth
Example: --proxy-basic --proxy-user user:passwd -x proxy $URL
Added: 7.12.0
---
Tells curl to use HTTP Basic authentication when communicating with the given
proxy. Use --basic for enabling HTTP Basic with a remote host. Basic is the
default authentication method curl uses with proxies.
