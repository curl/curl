Long: ftp-ssl-ccc-mode
Arg: <active/passive>
Help: Set CCC mode
Protocols: FTP
Added: 7.16.2
See-also: ftp-ssl-ccc
---
Sets the CCC mode. The passive mode will not initiate the shutdown, but
instead wait for the server to do it, and will not reply to the shutdown from
the server. The active mode initiates the shutdown and waits for a reply from
the server.
