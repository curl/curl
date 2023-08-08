c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: trace-ascii
Arg: <file>
Help: Like --trace, but without hex output
Mutexed: trace verbose
Category: verbose
Example: --trace-ascii log.txt $URL
Added: 7.9.7
See-also: verbose trace
Multi: single
Scope: global
---
Enables a full trace dump of all incoming and outgoing data, including
descriptive information, to the given output file. Use "-" as filename to have
the output sent to stdout.

This is similar to --trace, but leaves out the hex part and only shows the
ASCII part of the dump. It makes smaller output that might be easier to read
for untrained humans.

Note that verbose output of curl activities and network traffic might contain
sensitive data, including user names, credentials or secret data content. Be
aware and be careful when sharing trace logs with others.
