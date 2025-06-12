---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: false-start
Help: Enable TLS False Start
Protocols: TLS
Added: 7.42.0
Category: deprecated
Multi: boolean
See-also:
  - tcp-fastopen
Example:
  - --false-start $URL
---

# `--false-start`

No TLS backend currently supports this feature.

Use false start during the TLS handshake. False start is a mode where a TLS
client starts sending application data before verifying the server's Finished
message, thus saving a round trip when performing a full handshake.
