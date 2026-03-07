---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ssl-allow-beast
Help: Allow security flaw to improve interop
Protocols: TLS
Added: 7.25.0
Category: tls
Multi: boolean
See-also:
  - proxy-ssl-allow-beast
  - insecure
Example:
  - --ssl-allow-beast $URL
---

# `--ssl-allow-beast`

Do not work around a security flaw in the TLS1.0 protocol known as BEAST. If
this option is not used, the TLS layer may use workarounds known to cause
interoperability problems with some older server implementations.

This option only changes how curl does TLS 1.0 and has no effect on later TLS
versions.

**WARNING**: this option loosens the TLS security, and by using this flag you
ask for exactly that.
