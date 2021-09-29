Long: dump-header
Short: D
Arg: <filename>
Help: Write the received headers to <filename>
Protocols: HTTP FTP
See-also: output
Category: http ftp
Example: --dump-header store.txt $URL
Added: 5.7
---
Write the received protocol headers to the specified file. If no headers are
received, the use of this option will create an empty file.

When used in FTP, the FTP server response lines are considered being "headers"
and thus are saved there.

If this option is used several times, the last one will be used.
