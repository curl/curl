Long: etag-save
Arg: <file>
Help: Parse ETag from a request and save it to a file
Protocols: HTTP
Added: 7.68.0
Category: http
---
This option saves an HTTP ETag to the specified file. Etag is
usually part of headers returned by a request. When server sends an
ETag, it must be enveloped by a double quote. This option extracts the
ETag without the double quotes and saves it into the <file>.

A server can send a weak ETag which is prefixed by "W/". This identifier
is not considered, and only relevant ETag between quotation marks is parsed.

It an ETag wasn't sent by the server or it cannot be parsed, an empty
file is created.
