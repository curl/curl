c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: path-as-is
Help: Do not squash .. sequences in URL path
Added: 7.42.0
Category: curl
Example: --path-as-is https://example.com/../../etc/passwd
See-also: request-target
---
Tell curl to not handle sequences of /../ or /./ in the given URL
path. Normally curl will squash or merge them according to standards but with
this option set you tell it not to do that.
