---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ntlm-wb
Help: HTTP NTLM authentication with winbind
Protocols: HTTP
Category: auth http
Added: 7.22.0
Multi: mutex
See-also:
  - ntlm
  - proxy-ntlm
Example:
  - --ntlm-wb -u user:password $URL
---

# `--ntlm-wb`

Deprecated option (added in 8.8.0).

Enabled NTLM much in the style --ntlm does, but handed over the authentication
to a separate executable that was executed when needed.
