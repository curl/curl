c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tftp-blksize
Arg: <value>
Help: Set TFTP BLKSIZE option
Protocols: TFTP
Added: 7.20.0
Category: tftp
Example: --tftp-blksize 1024 tftp://example.com/file
See-also: tftp-no-options
Multi: single
---
Set the TFTP **BLKSIZE** option (must be >512). This is the block size that
curl tries to use when transferring data to or from a TFTP server. By
default 512 bytes are used.
