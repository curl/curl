---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-cert
Arg: <cert[:passwd]>
Help: Set client certificate for proxy
Added: 7.52.0
Category: proxy tls
Multi: single
See-also:
  - proxy
  - proxy-key
  - proxy-cert-type
Example:
  - --proxy-cert file -x https://proxy $URL
---

# `--proxy-cert`

Use the specified client certificate file when communicating with an HTTPS
proxy. The certificate must be in PKCS#12 format if using Secure Transport, or
PEM format if using any other engine. If the optional password is not
specified, it is queried for on the terminal. Use --proxy-key to provide the
private key.

This option is the equivalent to --cert but used in HTTPS proxy context.
