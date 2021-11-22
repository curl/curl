Short: B
Long: use-ascii
Help: Use ASCII/text transfer
Protocols: FTP LDAP
Category: misc
Example: -B ftp://example.com/README
Added: 5.0
See-also: crlf data-ascii
---
Enable ASCII transfer. For FTP, this can also be enforced by using a URL that
ends with ";type=A". This option causes data sent to stdout to be in text mode
for win32 systems.
