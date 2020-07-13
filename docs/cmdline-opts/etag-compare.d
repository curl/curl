Long: etag-compare
Arg: <file>
Help: Pass an ETag from a file as a custom header
Protocols: HTTP
Added: 7.68.0
Category: http
---
This option makes a conditional HTTP request for the specific
ETag read from the given file by sending a custom If-None-Match
header using the extracted ETag.

For correct results, make sure that specified file contains only a single
line with a desired ETag. An empty file is parsed as an empty ETag.

Use the option --etag-save to first save the ETag from a response, and
then use this option to compare using the saved ETag in a subsequent request.

\fCOMPARISON\fP: There are 2 types of comparison or ETags, Weak and Strong.
This option expects, and uses a strong comparison.
