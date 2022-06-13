c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: hostpubsha256
Arg: <sha256>
Help: Acceptable SHA256 hash of the host public key
Protocols: SFTP SCP
Added: 7.80.0
Category: sftp scp
Example: --hostpubsha256 NDVkMTQxMGQ1ODdmMjQ3MjczYjAyOTY5MmRkMjVmNDQ= sftp://example.com/
See-also: hostpubmd5
---
Pass a string containing a Base64-encoded SHA256 hash of the remote
host's public key. Curl will refuse the connection with the host
unless the hashes match.
