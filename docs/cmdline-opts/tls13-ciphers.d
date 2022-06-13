c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tls13-ciphers
Arg: <ciphersuite list>
help: TLS 1.3 cipher suites to use
Protocols: TLS
Category: tls
Example: --tls13-ciphers TLS_AES_128_GCM_SHA256 $URL
Added: 7.61.0
See-also: ciphers curves
---
Specifies which cipher suites to use in the connection if it negotiates TLS
1.3. The list of ciphers suites must specify valid ciphers. Read up on TLS 1.3
cipher suite details on this URL:

 https://curl.se/docs/ssl-ciphers.html

This option is currently used only when curl is built to use OpenSSL 1.1.1 or
later. If you are using a different SSL backend you can try setting TLS 1.3
cipher suites by using the --ciphers option.

If this option is used several times, the last one will be used.
