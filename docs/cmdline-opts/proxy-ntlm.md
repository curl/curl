---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-ntlm
Help: NTLM authentication with the proxy
Category: proxy auth
Added: 7.10.7
Multi: mutex
See-also:
  - proxy-negotiate
  - proxy-anyauth
Example:
  - --proxy-ntlm --proxy-user user:passwd -x http://proxy $URL
---

# `--proxy-ntlm`

Use HTTP NTLM authentication when communicating with the given proxy. Use
--ntlm for enabling NTLM with a remote host.
