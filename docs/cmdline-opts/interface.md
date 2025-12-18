---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: interface
Arg: <name>
Help: Use network interface
Category: connection
Added: 7.3
Multi: single
See-also:
  - dns-interface
Example:
  - --interface eth0 $URL
  - --interface "host!10.0.0.1" $URL
  - --interface "if!enp3s0" $URL
---

# `--interface`

Perform the operation using a specified interface. You can enter interface
name, IP address or hostname. If you prefer to be specific, you can use the
following special syntax:

## `if!<name>`

Interface name. If the provided name does not match an existing interface,
curl returns with error 45.

## `host!<name>`

IP address or hostname.

## `ifhost!<interface>!<host>`

Interface name and IP address or hostname. This syntax requires libcurl 8.9.0
or later.

If the provided name does not match an existing interface, curl returns with
error 45.

##

curl does not support using network interface names for this option on
Windows.

That name resolve operation if a hostname is provided does **not** use
DNS-over-HTTPS even if --doh-url is set.

On Linux this option can be used to specify a **VRF** (Virtual Routing and
Forwarding) device, but the binary then needs to either have the
**CAP_NET_RAW** capability set or to be run as root.
