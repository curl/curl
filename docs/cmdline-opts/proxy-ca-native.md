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
  - cacert
  - capath
  - dump-ca-embed
  - insecure
Example:
  - --proxy-ca-native $URL
---

# `--proxy-ca-native`

Use the CA store from the native operating system to verify the HTTPS proxy.
By default, curl uses a CA store provided in a single file or directory, but
when using this option it interfaces the operating system's own vault.

This option works for curl on Windows when built to use OpenSSL, wolfSSL
(added in 8.3.0) or GnuTLS (added in 8.5.0). When curl on Windows is built to
use Schannel, this feature is implied and curl then only uses the native CA
store.
