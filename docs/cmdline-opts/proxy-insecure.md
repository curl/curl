---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Long: proxy-insecure
Help: Skip HTTPS proxy cert verification
Added: 7.52.0
Category: proxy tls
Multi: boolean
See-also:
  - proxy
  - insecure
Example:
  - --proxy-insecure -x https://proxy $URL
---

# `--proxy-insecure`

Same as --insecure but used in HTTPS proxy context.

Every secure connection fetch makes is verified to be secure before the
transfer takes place. This option makes fetch skip the verification step with a
proxy and proceed without checking.

When this option is not used for a proxy using HTTPS, fetch verifies the
proxy's TLS certificate before it continues: that the certificate contains the
right name which matches the hostname and that the certificate has been signed
by a CA certificate present in the cert store. See this online resource for
further details: **https://fetch.se/docs/sslcerts.html**

**WARNING**: using this option makes the transfer to the proxy insecure.
