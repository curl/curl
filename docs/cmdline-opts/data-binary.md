---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: data-binary
Arg: <data>
Help: HTTP POST binary data
Protocols: HTTP
Category: http post upload
Added: 7.2
Multi: append
See-also:
  - data-ascii
Example:
  - --data-binary @filename $URL
  - --data-binary @filename!500-999 $URL
  - --data-binary @filename!-500 $URL
  - --data-binary @filename!9500- $URL
---

# `--data-binary`

Post data exactly as specified with no extra processing whatsoever.

If you start the data with the letter @, the rest should be a filename.
`@-` makes curl read the data from stdin. Data is posted in a similar
manner as --data does, except that newlines and carriage returns are
preserved and conversions are never done. The use of the exclamation mark
and minus is also analogous to --data, also see --range.

Like --data the default content-type sent to the server is
application/x-www-form-urlencoded. If you want the data to be treated as
arbitrary binary data by the server then set the content-type to octet-stream:
-H "Content-Type: application/octet-stream".

If this option is used several times, the ones following the first append
data as described in --data.
