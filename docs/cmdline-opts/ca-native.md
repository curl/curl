---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ca-native
Help: Load CA certs from the OS
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
  - --ca-native $URL
---

# `--ca-native`

Use the operating system's native CA store for certificate verification. If
you set this option and also set a CA certificate file or directory, or curl
was built with a default certificate location setting, then during verification
those certificates are searched in addition to the native CA store.

This option works for OpenSSL on Windows (added in 7.71.0).

This option works for wolfSSL on Windows, Linux (Debian, Ubuntu, Gentoo,
Fedora, RHEL), macOS, Android and iOS (added in 8.3.0).

This option works for GnuTLS (added in 8.5.0).

This option has no effect on Schannel. Schannel is the native TLS library for
Windows and therefore already uses the native CA store for verification unless
it is overridden by a certificate location setting.