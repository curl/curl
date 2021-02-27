Long: ssl-no-default-creds
Help: Do not use default credentials (Schannel)
Added: 7.76.0
See-also: proxy-ssl-no-default-creds
Category: tls
---
Tell libcurl to not automatically locate and use a client certificate for
authentication. This option is only supported for Schannel (the native Windows
SSL library). By default, Schannel will, with no notification to the client,
attempt to locate a client certificate and send it to the server (when
requested by the server). That could be considered a privacy violation and
unexpected.
