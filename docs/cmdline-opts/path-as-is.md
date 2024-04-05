---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: path-as-is
Help: Do not squash .. sequences in URL path
Added: 7.42.0
Category: curl
Multi: boolean
See-also:
  - request-target
Example:
  - --path-as-is https://example.com/../../etc/passwd
---

# `--path-as-is`

Do not handle sequences of /../ or /./ in the given URL path. Normally curl
squashes or merges them according to standards but with this option set you
tell it not to do that.
