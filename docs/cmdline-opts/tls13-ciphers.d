Long: tls13-ciphers
Arg: <list of TLS 1.3 ciphersuites>
help: TLS 1.3 cipher suites to use
Protocols: TLS
---
Specifies which cipher suites to use in the connection if it negotiates TLS
1.3. The list of ciphers suites must specify valid ciphers. Read up on TLS 1.3
cipher suite details on this URL:

 https://curl.haxx.se/docs/ssl-ciphers.html

If this option is used several times, the last one will be used.
