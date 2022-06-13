c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proto-default
Help: Use PROTOCOL for any URL missing a scheme
Arg: <protocol>
Added: 7.45.0
Category: connection curl
Example: --proto-default https ftp.example.com
See-also: proto proto-redir
---
Tells curl to use *protocol* for any URL missing a scheme name.

An unknown or unsupported protocol causes error
*CURLE_UNSUPPORTED_PROTOCOL* (1).

This option does not change the default proxy protocol (http).

Without this option set, curl guesses protocol based on the host name, see
--url for details.
