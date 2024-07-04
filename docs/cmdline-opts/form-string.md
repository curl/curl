---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: form-string
Help: Specify multipart MIME data
Protocols: HTTP SMTP IMAP
Arg: <name=string>
Category: http upload post smtp imap
Added: 7.13.2
Multi: append
See-also:
  - form
Example:
  - --form-string "name=data" $URL
---

# `--form-string`

Similar to --form except that the value string for the named parameter is used
literally. Leading @ and \< characters, and the `;type=` string in the value
have no special meaning. Use this in preference to --form if there is any
possibility that the string value may accidentally trigger the @ or \<
features of --form.
