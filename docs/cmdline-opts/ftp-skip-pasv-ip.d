Long: ftp-skip-pasv-ip
Help: Skip the IP address for PASV
Protocols: FTP
Added: 7.14.2
See-also: ftp-pasv
Category: ftp
---
Tell curl to not use the IP address the server suggests in its response
to curl's PASV command when curl connects the data connection. Instead curl
will re-use the same IP address it already uses for the control
connection.

Since curl 7.74.0 this option is enabled by default.

This option has no effect if PORT, EPRT or EPSV is used instead of PASV.
