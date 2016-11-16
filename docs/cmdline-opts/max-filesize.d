Long: max-filesize
Arg: <bytes>
Help: Maximum file size to download
See-also: limit-rate
---
Specify the maximum size (in bytes) of a file to download. If the file
requested is larger than this value, the transfer will not start and curl will
return with exit code 63.

\fBNOTE:\fP The file size is not always known prior to download, and for such
files this option has no effect even if the file transfer ends up being larger
than this given limit. This concerns both FTP and HTTP transfers.
