---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: interface
Arg: <name>
Help: Use network INTERFACE (or address)
Category: connection
Added: 7.3
Multi: single
See-also:
  - dns-interface
Example:
  - --interface eth0 $URL
---

# `--interface`

Perform an operation using a specified interface. You can enter interface
name, IP address or host name. An example could look like:

    curl --interface eth0:1 https://www.example.com/

On Linux it can be used to specify a **VRF**, but the binary needs to either
have **CAP_NET_RAW** or to be run as root. More information about Linux
**VRF**: https://www.kernel.org/doc/Documentation/networking/vrf.txt
