c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: max-filesize
Arg: <bytes>
Help: Maximum file size to download
Protocols: FTP HTTP MQTT
See-also: limit-rate
Category: connection
Example: --max-filesize 100K $URL
Added: 7.10.8
Multi: single
---
Specify the maximum size (in bytes) of a file to download. If the file
requested is larger than this value, the transfer will not start and curl will
return with exit code 63.

A size modifier may be used. For example, Appending 'k' or 'K' will count the
number as kilobytes, 'm' or 'M' makes it megabytes, while 'g' or 'G' makes it
gigabytes. Examples: 200K, 3m and 1G. (Added in 7.58.0)

**NOTE**: The file size is not always known prior to download. In this case,
curl will start the download and if the received data exceeds the maximum size
then curl will terminate the transfer prematurely and return error 63. Prior to
curl 8.4.0 the option would have no effect in this case.
