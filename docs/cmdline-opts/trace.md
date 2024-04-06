---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: trace
Arg: <file>
Help: Write a debug trace to FILE
Mutexed: verbose trace-ascii
Category: verbose
Added: 7.9.7
Multi: single
Scope: global
See-also:
  - trace-ascii
  - trace-config
  - trace-ids
  - trace-time
Example:
  - --trace log.txt $URL
---

# `--trace`

Save a full trace dump of all incoming and outgoing data, including
descriptive information, in the given output file. Use "-" as filename to have
the output sent to stdout. Use "%" as filename to have the output sent to
stderr.

Note that verbose output of curl activities and network traffic might contain
sensitive data, including usernames, credentials or secret data content. Be
aware and be careful when sharing trace logs with others.
