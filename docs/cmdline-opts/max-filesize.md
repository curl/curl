---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: max-filesize
Arg: <bytes>
Help: Maximum file size to download
Protocols: FTP HTTP MQTT
Category: connection
Added: 7.10.8
Multi: single
See-also:
  - limit-rate
Example:
  - --max-filesize 100K $URL
---

# `--max-filesize`

Specify the maximum size (in bytes) of a file to download. If the file
requested is larger than this value, the transfer does not start and curl
returns with exit code 63.

A size modifier may be used. For example, Appending 'k' or 'K' counts the
number as kilobytes, 'm' or 'M' makes it megabytes, while 'g' or 'G' makes it
gigabytes. Examples: 200K, 3m and 1G. (Added in 7.58.0)

**NOTE**: before curl 8.4.0, when the file size is not known prior to
download, for such files this option has no effect even if the file transfer
ends up being larger than this given limit.

Starting with curl 8.4.0, this option aborts the transfer if it reaches the
threshold during transfer.
