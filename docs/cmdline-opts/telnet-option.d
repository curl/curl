c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: telnet-option
Short: t
Arg: <opt=val>
Help: Set telnet option
Category: telnet
Example: -t TTYPE=vt100 telnet://example.com/
Added: 7.7
See-also: config
Multi: append
---
Pass options to the telnet protocol. Supported options are:

.RS
.TP 15
**TTYPE**=<term> Sets the terminal type.
.TP
**XDISPLOC**=<X display> Sets the X display location.
.TP
**NEW_ENV**=<var,val> Sets an environment variable.
.RE
.IP
