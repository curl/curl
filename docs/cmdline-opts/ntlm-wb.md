---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ntlm-wb
Help: Use HTTP NTLM authentication with winbind
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

Enables NTLM much in the style --ntlm does, but hand over the authentication
to the separate binary `ntlmauth` application that is executed when needed.
