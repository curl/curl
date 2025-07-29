---
c: Copyright (C) Dorian Craps, <dorian.craps@student.vinci.be>
SPDX-License-Identifier: curl
Long: mptcp
Added: 8.9.0
Help: Enable Multipath TCP
Category: connection
Multi: boolean
See-also:
  - tcp-fastopen
Example:
  - --mptcp $URL
---

# `--mptcp`

Enable the use of Multipath TCP (MPTCP) for connections. MPTCP is an extension
to the standard TCP that allows multiple TCP streams over different network
paths between the same source and destination. This can enhance bandwidth and
improve reliability by using multiple paths simultaneously.

MPTCP is beneficial in networks where multiple paths exist between clients and
servers, such as mobile networks where a device may switch between WiFi and
cellular data or in wired networks with multiple Internet Service Providers.

This option is currently only supported on Linux starting from kernel 5.6. Only
TCP connections are modified, hence this option does not affect HTTP/3 (QUIC)
or UDP connections.

The server curl connects to must also support MPTCP. If not, the connection
seamlessly falls back to TCP.
