c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: trace
Arg: <file>
Help: Write a debug trace to FILE
Mutexed: verbose trace-ascii
Category: verbose
Example: --trace log.txt $URL
Added: 7.9.7
See-also: trace-ascii trace-time
Multi: single
---
Enables a full trace dump of all incoming and outgoing data, including
descriptive information, to the given output file. Use "-" as filename to have
the output sent to stdout. Use "%" as filename to have the output sent to
stderr.

This option is global and does not need to be specified for each use of
--next.
