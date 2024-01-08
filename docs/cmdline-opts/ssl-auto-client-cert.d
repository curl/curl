c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ssl-auto-client-cert
Help: Use auto client certificate (Schannel)
Added: 7.77.0
See-also: proxy-ssl-auto-client-cert
Category: tls
Protocols: TLS
Example: --ssl-auto-client-cert $URL
Multi: boolean
---
(Schannel) Tell libcurl to automatically locate and use a client certificate
for authentication, when requested by the server. Since the server can request
any certificate that supports client authentication in the OS certificate
store it could be a privacy violation and unexpected.
