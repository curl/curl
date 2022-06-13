c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: egd-file
Arg: <file>
Help: EGD socket path for random data
Protocols: TLS
See-also: random-file
Category: tls
Example: --egd-file /random/here $URL
Added: 7.7
---
Deprecated option. This option is ignored by curl since 7.84.0. Prior to that
it only had an effect on curl if built to use old versions of OpenSSL.

Specify the path name to the Entropy Gathering Daemon socket. The socket is
used to seed the random engine for SSL connections.
