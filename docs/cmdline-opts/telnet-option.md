---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: telnet-option
Short: t
Arg: <opt=val>
Help: Set telnet option
Category: telnet
Added: 7.7
Multi: append
See-also:
  - config
Example:
  - -t TTYPE=vt100 telnet://example.com/
---

# `--telnet-option`

Pass options to the telnet protocol. Supported options are:

## `TTYPE=<term>`
Sets the terminal type.

## `XDISPLOC=<X display>`
Sets the X display location.

## `NEW_ENV=<var,val>`
Sets an environment variable.
