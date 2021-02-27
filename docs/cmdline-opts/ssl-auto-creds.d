Long: ssl-auto-creds
Help: Use auto credentials (Schannel)
Added: 7.76.0
See-also: proxy-ssl-auto-creds
Category: tls
---
Tell libcurl to automatically locate and use a client certificate for
authentication, when requested by the server. This option is only supported
for Schannel (the native Windows SSL library). Prior to 7.76.0 this was the
default behavior in libcurl with Schannel. Since the server can request any
certificate that supports client authentication in the OS certificate store it
could be a privacy violation and unexpected.
