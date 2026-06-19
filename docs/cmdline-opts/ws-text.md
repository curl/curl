---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ws-text
Help: Send WebSocket text frames by default
Category: websocket
Added: 8.21.0
Multi: single
See-also:
  - ws-binary
Example:
  - --ws-text -o storage $URL
---

# `--ws-text`

Tell curl to send WebSocket text frames by default. This option and the related
`--ws-binary` option determine the type of frame sent by curl to a WebSocket
server. If neither option is given, the default is to send text frames. If both
options are used, the last one wins.
