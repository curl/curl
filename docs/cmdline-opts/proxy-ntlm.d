Long: proxy-ntlm
Help: Use NTLM authentication on the proxy
See-also: proxy-negotiate proxy-anyauth
Category: proxy auth
Example: --proxy-ntlm --proxy-user user:passwd -x http://proxy $URL
---
Tells curl to use HTTP NTLM authentication when communicating with the given
proxy. Use --ntlm for enabling NTLM with a remote host.
