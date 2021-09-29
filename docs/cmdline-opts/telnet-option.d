Long: telnet-option
Short: t
Arg: <opt=val>
Help: Set telnet option
Category: telnet
Example: -t TTYPE=vt100 telnet://example.com/
Added: 7.7
---
Pass options to the telnet protocol. Supported options are:

TTYPE=<term> Sets the terminal type.

XDISPLOC=<X display> Sets the X display location.

NEW_ENV=<var,val> Sets an environment variable.
