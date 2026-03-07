---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-ca-native
Help: Load CA certs from the OS to verify proxy
Protocols: TLS
Category: tls
Added: 8.2.0
Multi: boolean
See-also:
  - ca-native
  - cacert
  - capath
  - dump-ca-embed
  - insecure
Example:
  - --proxy-ca-native $URL
---

# `--proxy-ca-native`

Use the operating system's native CA store for certificate verification of the
HTTPS proxy.

This option is independent of other HTTPS proxy CA certificate locations set at
run time or build time. Those locations are searched in addition to the native
CA store.

Equivalent to --ca-native but used in HTTPS proxy context. Refer to --ca-native
for TLS backend limitations.
