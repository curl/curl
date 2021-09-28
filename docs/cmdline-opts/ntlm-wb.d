Long: ntlm-wb
Help: Use HTTP NTLM authentication with winbind
Protocols: HTTP
See-also: ntlm proxy-ntlm
Category: auth http
Example: --ntlm-wb -u user:password $URL
Added: 7.22.0
---
Enables NTLM much in the style --ntlm does, but hand over the authentication
to the separate binary ntlmauth application that is executed when needed.
