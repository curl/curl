---
c: Copyright (C) Dorian Craps, <dorian.craps@student.vinci.be>
SPDX-License-Identifier: curl
Long: mptcp
Added: 8.7.0
Help: Enable Multipath TCP (MPTCP)
Category: connection
Multi: boolean
See-also:
  - tcp-fastopen
Example:
  - --mptcp $URL
---

# `--mptcp`

Enables the use of Multipath TCP (MPTCP) for connections. MPTCP is an extension 
to the standard TCP that allows multiple TCP streams over different network 
paths between the same source and destination. This can enhance bandwidth and 
improve reliability by using multiple paths simultaneously.

MPTCP is beneficial in networks where multiple paths exist between clients and 
servers, such as mobile networks where a device may switch between Wi-Fi and 
cellular data or in wired networks with multiple ISPs.

## Usage

To use MPTCP for your connections, add the `--mptcp` option when using `curl`:

## Requirements

- Your operating system must support MPTCP, and it must be enabled.
- The server you are connecting to must also support MPTCP.

## Availability

The `--mptcp` option is available starting from `curl` version 8.6.1.
