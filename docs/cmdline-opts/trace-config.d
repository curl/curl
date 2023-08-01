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
Multi: single
Scope: global
---
Set configuration for trace output. A comma-separated list of components
where detailed output will be made available. Specify 'all' to enable all
details.
