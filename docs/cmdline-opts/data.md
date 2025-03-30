---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: data
Short: d
Arg: <data>
Help: HTTP POST data
Protocols: HTTP MQTT
Mutexed: form head upload-file
Category: important http post upload
Added: 4.0
Multi: append
See-also:
  - data-binary
  - data-urlencode
  - data-raw
Example:
  - -d "name=curl" $URL
  - -d "name=curl" -d "tool=cmdline" $URL
  - -d @filename $URL
---

# `--data`

Send the specified data in a POST request to the HTTP server, in the same way
that a browser does when a user has filled in an HTML form and presses the
submit button. This option makes curl pass the data to the server using the
content-type application/x-www-form-urlencoded. Compare to --form.

--data-raw is almost the same but does not have a special interpretation of
the @ character. To post data purely binary, you should instead use the
--data-binary option. To URL-encode the value of a form field you may use
--data-urlencode.

If any of these options is used more than once on the same command line, the
data pieces specified are merged with a separating &-symbol. Thus, using
'-d name=daniel -d skill=lousy' would generate a post chunk that looks like
'name=daniel&skill=lousy'.

If you start the data with the letter @, the rest should be a filename to read
the data from, or - if you want curl to read the data from stdin. Posting data
from a file named 'foobar' would thus be done with --data @foobar. When --data
is told to read from a file like that, carriage returns, newlines and null
bytes are stripped out. If you do not want the @ character to have a special
interpretation use --data-raw instead.

The data for this option is passed on to the server exactly as provided on the
command line. curl does not convert, change or improve it. It is up to the
user to provide the data in the correct form.
