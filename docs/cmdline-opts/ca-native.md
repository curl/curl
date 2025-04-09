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
  - proxy-ca-native
Example:
  - --ca-native $URL
---

# `--ca-native`

Use the operating system's native CA store for certificate verification.

This option is independent of other CA certificate locations set at run time or
build time. Those locations are searched in addition to the native CA store.

This option works with OpenSSL and its forks (LibreSSL, BoringSSL, etc) on
Windows. (Added in 7.71.0)

This option works with wolfSSL on Windows, Linux (Debian, Ubuntu, Gentoo,
Fedora, RHEL), macOS, Android and iOS. (Added in 8.3.0)

This option works with GnuTLS. (Added in 8.5.0)

This options works with rustls on Windows, macOS, Android and iOS. On Linux it
is equivalent to using the Mozilla CA certificate bundle. When used with rustls
_only_ the native CA store is consulted, not other locations set at run time or
build time. (Added in 8.13.0)

This option currently has no effect for Schannel or Secure Transport. Those are
native TLS libraries from Microsoft and Apple, respectively, that by default
use the native CA store for verification unless overridden by a CA certificate
location setting.
