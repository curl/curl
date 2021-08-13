Long: ignore-content-length
Help: Ignore the size of the remote resource
Protocols: FTP HTTP
Category: http ftp
---
For HTTP, Ignore the Content-Length header. This is particularly useful for
servers running Apache 1.x, which will report incorrect Content-Length for
files larger than 2 gigabytes.

For FTP (since 7.46.0), skip the RETR command to figure out the size before
downloading a file.

This option doesn't work if libcurl was built to use hyper for HTTP.
