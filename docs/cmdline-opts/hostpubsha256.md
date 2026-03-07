---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: hostpubsha256
Arg: <sha256>
Help: Acceptable SHA256 hash of host public key
Protocols: SFTP SCP
Added: 7.80.0
Category: sftp scp ssh
Multi: single
See-also:
  - hostpubmd5
Example:
  - --hostpubsha256 NDVkMTQxMGQ1ODdmMjQ3MjczYjAyOTY5MmRkMjVmNDQ= sftp://example.com/
---

# `--hostpubsha256`

Pass a string containing a Base64-encoded SHA256 hash of the remote host's
public key. curl refuses the connection with the host unless the hashes match.

This feature requires libcurl to be built with libssh2 and does not work with
other SSH backends.
