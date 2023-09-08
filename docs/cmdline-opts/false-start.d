c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: false-start
Help: Enable TLS False Start
Protocols: TLS
Added: 7.42.0
Category: tls
Example: --false-start $URL
See-also: tcp-fastopen
Multi: boolean
---
Tells curl to use false start during the TLS handshake. False start is a mode
where a TLS client starts sending application data before verifying the
server's Finished message, thus saving a round trip when performing a full
handshake.

This is currently only implemented in the Secure Transport (on iOS 7.0 or
later, or OS X 10.9 or later) backend.
