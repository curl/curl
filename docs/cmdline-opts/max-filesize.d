Long: max-filesize
Arg: <bytes>
Help: Maximum file size to download
See-also: limit-rate
Category: connection
---
Specify the maximum size (in bytes) of a file to download. If the file
requested is larger than this value, the transfer will not start and curl will
return with exit code 63.

A size modifier may be used. For example, Appending 'k' or 'K' will count the
number as kilobytes, 'm' or 'M' makes it megabytes, while 'g' or 'G' makes it
gigabytes. Examples: 200K, 3m and 1G. (Added in 7.58.0)

**NOTE**: For protocols where the size is not known in advance (including FTP
and HTTP) this option has no effect even if the file transfer ends up being
larger than the given limit.
