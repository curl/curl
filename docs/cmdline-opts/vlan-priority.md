---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: vlan-priority
Arg: <priority>
Help: Set VLAN priority
Added: 8.9.0
Category: connection
Protocols: All
Multi: single
See-also:
  - ip-tos
Example:
  - --vlan-priority 4 $URL
---

# `--vlan-priority`

Set VLAN priority as defined in IEEE 802.1Q.

This field is set on Ethernet level, and only works within a local network.

The valid range for \<priority\> is 0 to 7.
