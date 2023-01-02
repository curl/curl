c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-negotiate
Help: Use HTTP Negotiate (SPNEGO) authentication on the proxy
Added: 7.17.1
See-also: proxy-anyauth proxy-basic
Category: proxy auth
Example: --proxy-negotiate --proxy-user user:passwd -x proxy $URL
Multi: mutex
---
Tells curl to use HTTP Negotiate (SPNEGO) authentication when communicating
with the given proxy. Use --negotiate for enabling HTTP Negotiate (SPNEGO)
with a remote host.
