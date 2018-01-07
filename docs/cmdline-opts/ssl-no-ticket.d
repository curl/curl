Long: ssl-no-ticket
Help: Disable curl's use of SSL session-ticket rusing(OpensslSSL)
Protocols: TLS
Added: 7.58.0
---
(OpenSSL) This option tells curl to disable SSL session ticket during the ssl handshake.

for example:
 curl https://www.example.com/ -v --ssl-session-file /tmp/sess.pem --ssl-no-ticket

