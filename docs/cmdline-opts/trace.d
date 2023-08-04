c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: trace
Arg: <file>
Help: Write a debug trace to FILE
Mutexed: verbose trace-ascii
Category: verbose
Example: --trace log.txt $URL
Added: 7.9.7
See-also: trace-ascii trace-config trace-ids trace-time
Multi: single
Scope: global
---
Enables a full trace dump of all incoming and outgoing data, including
descriptive information, to the given output file. Use "-" as filename to have
the output sent to stdout. Use "%" as filename to have the output sent to
stderr.

Note that verbose output of curl activities and network traffic might contain
sensitive data, including user names, credentials or secret data content. Be
aware and be careful when sharing trace logs with others.
