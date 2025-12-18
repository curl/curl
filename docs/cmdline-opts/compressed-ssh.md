---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: compressed-ssh
Help: Enable SSH compression
Protocols: SCP SFTP
Added: 7.56.0
Category: scp ssh
Multi: boolean
See-also:
  - compressed
Example:
  - --compressed-ssh sftp://example.com/
---

# `--compressed-ssh`

Enable SSH compression. This is a request, not an order; the server may or may
not do it. This allows the data to be sent compressed over the wire, and
automatically decompressed in the receiving end, to save bandwidth.
