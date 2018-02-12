Long: ftp-ssl-control
Help: Require SSL/TLS for FTP login, clear for transfer
Protocols: FTP
Added: 7.16.0
---
Require SSL/TLS for the FTP login, clear for transfer.  Allows secure
authentication, but non-encrypted data transfers for efficiency.  Fails the
transfer if the server doesn't support SSL/TLS.
