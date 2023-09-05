c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ntlm
Help: Use HTTP NTLM authentication
Mutexed: basic negotiate digest anyauth
See-also: proxy-ntlm
Protocols: HTTP
Requires: TLS
Category: auth http
Example: --ntlm -u user:password $URL
Added: 7.10.6
Multi: mutex
---
Enables NTLM authentication. The NTLM authentication method was designed by
Microsoft and is used by IIS web servers. It is a proprietary protocol,
reverse-engineered by clever people and implemented in curl based on their
efforts. This kind of behavior should not be endorsed, you should encourage
everyone who uses NTLM to switch to a public and documented authentication
method instead, such as Digest.

If you want to enable NTLM for your proxy authentication, then use
--proxy-ntlm.
