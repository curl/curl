Long: proxy-tls13-ciphers
Arg: <ciphersuite list>
help: TLS 1.3 proxy cipher suites
Protocols: TLS
Category: proxy tls
---
Specifies which cipher suites to use in the connection to your HTTPS proxy
when it negotiates TLS 1.3. The list of ciphers suites must specify valid
ciphers. Read up on TLS 1.3 cipher suite details on this URL:

 https://curl.se/docs/ssl-ciphers.html

This option is currently used only when curl is built to use OpenSSL 1.1.1 or
later. If you are using a different SSL backend you can try setting TLS 1.3
cipher suites by using the --proxy-ciphers option.

If this option is used several times, the last one will be used.
