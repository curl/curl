---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ignore-content-length
Help: Ignore the size of the remote resource
Protocols: FTP HTTP
Category: http ftp
Added: 7.14.1
Multi: boolean
See-also:
  - ftp-skip-pasv-ip
Example:
  - --ignore-content-length $URL
---

# `--ignore-content-length`

For HTTP, ignore the Content-Length header. This is particularly useful for
servers running Apache 1.x, which reports incorrect Content-Length for files
larger than 2 gigabytes.

For FTP, this makes curl skip the SIZE command to figure out the size before
downloading a file (added in 7.46.0).
