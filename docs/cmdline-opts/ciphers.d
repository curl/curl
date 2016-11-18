Long: ciphers
Arg: <list of ciphers>
help: SSL ciphers to use
Protocols: TLS
---
Specifies which ciphers to use in the connection. The list of ciphers must
specify valid ciphers. Read up on SSL cipher list details on this URL:

 https://www.openssl.org/docs/apps/ciphers.html

NSS ciphers are done differently than OpenSSL and GnuTLS. The full list of NSS
ciphers is in the NSSCipherSuite entry at this URL:

 https://git.fedorahosted.org/cgit/mod_nss.git/plain/docs/mod_nss.html#Directives

If this option is used several times, the last one will be used.
