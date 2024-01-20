---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: hostpubmd5
Arg: <md5>
Help: Acceptable MD5 hash of the host public key
Protocols: SFTP SCP
Added: 7.17.1
Category: sftp scp
Multi: single
See-also:
  - hostpubsha256
Example:
  - --hostpubmd5 e5c1c49020640a5ab0f2034854c321a8 sftp://example.com/
---

# `--hostpubmd5`

Pass a string containing 32 hexadecimal digits. The string should be the 128
bit **MD5** checksum of the remote host's public key, curl refuses the
connection with the host unless the checksums match.
