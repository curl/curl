c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: trace-config
Arg: <string>
Help: enable
Mutexed: trace verbose
Category: verbose
Example: --trace-config ids,http/2 $URL
Added: 8.3.0
See-also: verbose trace
Multi: append
Scope: global
---
Set configuration for trace output. A comma-separated list of components where
detailed output can be made available from. Names are case-insensitive.
Specify 'all' to enable all trace components.

In addition to trace component names, specify "ids" and "time" to
avoid extra --trace-ids or --trace-time parameters.

See the *curl_global_trace(3)* man page for more details.
