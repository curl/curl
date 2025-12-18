---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: egd-file
Arg: <file>
Help: EGD socket path for random data
Protocols: TLS
Category: deprecated
Added: 7.7
Multi: single
See-also:
  - random-file
Example:
  - --egd-file /random/here $URL
---

# `--egd-file`

Deprecated option (added in 7.84.0). Prior to that it only had an effect on
curl if built to use old versions of OpenSSL.

Specify the path name to the Entropy Gathering Daemon socket. The socket is
used to seed the random engine for SSL connections.
