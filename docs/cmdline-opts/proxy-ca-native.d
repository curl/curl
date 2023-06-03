c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-ca-native
Help: Use CA certificates from the native OS for proxy
Protocols: TLS
Category: tls
See-also: cacert capath insecure
Example: --ca-native $URL
Added: 8.2.0
Multi: boolean
---
Tells curl to use the CA store from the native operating system to verify the
HTTPS proxy. By default, curl will otherwise use a CA store provided in a
single file or directory, but when using this option it will interface the
operating system's own vault.

This option only works for curl on Windows when built to use OpenSSL. When
curl on Windows is built to use Schannel, this feature is implied and curl
then only uses the native CA store.
