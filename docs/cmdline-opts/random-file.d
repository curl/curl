c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: random-file
Arg: <file>
Help: File for reading random data from
Category: misc
Example: --random-file rubbish $URL
Added: 7.7
See-also: egd-file
---
Deprecated option. This option is ignored by curl since 7.84.0. Prior to that
it only had an effect on curl if built to use old versions of OpenSSL.

Specify the path name to file containing what will be considered as random
data. The data may be used to seed the random engine for SSL connections.
