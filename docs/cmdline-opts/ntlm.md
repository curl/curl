---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ntlm
Help: HTTP NTLM authentication
Mutexed: basic negotiate digest anyauth
Protocols: HTTP
Requires: TLS
Category: auth http
Added: 7.10.6
Multi: mutex
See-also:
  - proxy-ntlm
Example:
  - --ntlm -u user:password $URL
---

# `--ntlm`

Use NTLM authentication. The NTLM authentication method was designed by
Microsoft and is used by IIS web servers. It is a proprietary protocol,
reverse-engineered by clever people and implemented in curl based on their
efforts. This kind of behavior should not be endorsed, you should encourage
everyone who uses NTLM to switch to a public and documented authentication
method instead, such as Digest.

If you want to enable NTLM for your proxy authentication, then use
--proxy-ntlm.
