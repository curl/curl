Long: etag-save
Arg: <file>
Help: Parse ETag from a request and save it to a file
Protocols: HTTP
Added: 7.68.0
---
This option saves an HTTP ETag to the specified file. Etag is
usually part of headers returned by a request. When server sends an
ETag, curls extracts it and saves it into the <file>.

It an ETag wasn't send by the server or it cannot be parsed, and empty
file is created.
