Long: dump-header
Short: D
Arg: <filename>
Help: Write the received headers to <filename>
Protocols: HTTP FTP
See-also: output
---
Write the received protocol headers to the specified file.

This option is handy to use when you want to store the headers that an HTTP
site sends to you. Cookies from the headers could then be read in a second
curl invocation by using the --cookie option! The --cookie-jar option is a
better way to store cookies.

When used in FTP, the FTP server response lines are considered being "headers"
and thus are saved there.

If this option is used several times, the last one will be used.
