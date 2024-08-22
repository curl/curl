---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: v
Long: verbose
Mutexed: trace trace-ascii
Help: Make the operation more talkative
Category: important verbose global
Added: 4.0
Multi: boolean
Scope: global
See-also:
  - show-headers
  - silent
  - trace
  - trace-ascii
Example:
  - --verbose $URL
---

# `--verbose`

Makes curl verbose during the operation. Useful for debugging and seeing
what's going on under the hood. A line starting with \> means header data sent
by curl, \< means header data received by curl that is hidden in normal cases,
and a line starting with * means additional info provided by curl.

If you only want HTTP headers in the output, --show-headers or --dump-header
might be more suitable options.

Since curl 8.10, mentioning this option several times in the same argument
increases the level of the trace output. However, as before, a single
--verbose or --no-verbose reverts any additions by previous `-vv` again. This
means that `-vv -v` is equivalent to a single -v. This avoids unwanted
verbosity when the option is mentioned in the command line *and* curl config
files.

Using it twice, e.g. `-vv`, outputs time (--trace-time) and transfer ids
(--trace-ids), as well as enable tracing for all protocols (--trace-config
protocol).

Adding a third verbose outputs transfer content (--trace-ascii %) and enable
tracing of more components (--trace-config read,write,ssl).

A forth time adds tracing of all network components. (--trace-config network).

Any addition of the verbose option after that has no effect.

If you think this option does not give you the right details, consider using
--trace or --trace-ascii instead. Or use it only once and use --trace-config
to trace the specific components you wish to see.

Note that verbose output of curl activities and network traffic might contain
sensitive data, including usernames, credentials or secret data content. Be
aware and be careful when sharing trace logs with others.
