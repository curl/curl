---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: trace-config
Arg: <string>
Help: Details to log in trace/verbose output
Mutexed: trace verbose
Category: verbose
Added: 8.3.0
Multi: append
Scope: global
See-also:
  - verbose
  - trace
Example:
  - --trace-config ids,http/2 $URL
---

# `--trace-config`

Set configuration for trace output. A comma-separated list of components where
detailed output can be made available from. Names are case-insensitive.
Specify 'all' to enable all trace components.

In addition to trace component names, specify "ids" and "time" to
avoid extra --trace-ids or --trace-time parameters.

See the *curl_global_trace(3)* man page for more details.
