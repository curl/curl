Long: ftp-ssl-ccc
Help: Send CCC after authenticating
Protocols: FTP
See-also: ssl ftp-ssl-ccc-mode
Added: 7.16.1
---
Use CCC (Clear Command Channel) Shuts down the SSL/TLS layer after
authenticating. The rest of the control channel communication will be
unencrypted. This allows NAT routers to follow the FTP transaction. The
default mode is passive.
