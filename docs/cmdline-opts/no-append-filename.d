c: This is in the public domain
SPDX-License-Identifier: curl
Long: no-append-filename
Help: Inhibit appending the filename to URL when uploading
Protocols: HTTP
Category: http
Example: --no-append-filename --upload-file filename $URL
Added: 8.1.3
See-also: upload-file
Multi: boolean
---
Normally when uploading a file with the --upload-file option curl and
the URL has a trailing / curl will append the filename to the specified
URL.  This may fail if you are doing a PUT to a specific REST API
endpoint.  You can use --no-append-filename to suppress this behavior.

Note that this is the negated option name documented.  You can thus use
--append-filename to enable appending the filename to the URL.
