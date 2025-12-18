---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-ssl-allow-beast
Help: Allow this security flaw for HTTPS proxy
Added: 7.52.0
Category: proxy tls
Multi: boolean
See-also:
  - ssl-allow-beast
  - proxy
Example:
  - --proxy-ssl-allow-beast -x https://proxy $URL
---

# `--proxy-ssl-allow-beast`

Do not work around a security flaw in the TLS1.0 protocol known as BEAST when
communicating to an HTTPS proxy. If this option is not used, the TLS layer may
use workarounds known to cause interoperability problems with some older
server implementations.

This option only changes how curl does TLS 1.0 with an HTTPS proxy and has no
effect on later TLS versions.

**WARNING**: this option loosens the TLS security, and by using this flag you
ask for exactly that.

Equivalent to --ssl-allow-beast but used in HTTPS proxy context.
