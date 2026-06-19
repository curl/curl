---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ws-binary
Help: Send WebSocket binary frames by default
Category: websocket
Added: 8.21.0
Multi: single
See-also:
  - ws-text
Example:
  - --ws-binary -o storage $URL
---

# `--ws-binary`

Tell curl to send WebSocket binary frames by default. This option and the
related `--ws-text` option determine the type of frame sent by curl to a
WebSocket server.  If neither option is given, the default is to send text
frames. If both options are used, the last one wins.
