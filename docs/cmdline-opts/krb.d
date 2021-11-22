Long: krb
Arg: <level>
Help: Enable Kerberos with security <level>
Protocols: FTP
Requires: Kerberos
Category: ftp
Example: --krb clear ftp://example.com/
Added: 7.3
See-also: delegation ssl
---
Enable Kerberos authentication and use. The level must be entered and should
be one of 'clear', 'safe', 'confidential', or 'private'. Should you use a
level that is not one of these, 'private' will instead be used.

If this option is used several times, the last one will be used.
