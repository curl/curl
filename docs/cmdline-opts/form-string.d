c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: form-string
Help: Specify multipart MIME data
Protocols: HTTP SMTP IMAP
Arg: <name=string>
See-also: form
Category: http upload
Example: --form-string "data" $URL
Added: 7.13.2
---
Similar to --form except that the value string for the named parameter is used
literally. Leading '@' and '<' characters, and the ';type=' string in
the value have no special meaning. Use this in preference to --form if
there's any possibility that the string value may accidentally trigger the
'@' or '<' features of --form.
