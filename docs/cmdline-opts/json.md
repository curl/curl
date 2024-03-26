---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: json
Arg: <data>
Help: HTTP POST JSON
Protocols: HTTP
Mutexed: form head upload-file
Category: http post upload
Added: 7.82.0
Multi: append
See-also:
  - data-binary
  - data-raw
Example:
  - --json '{ "drink": "coffe" }' $URL
  - --json '{ "drink":' --json ' "coffe" }' $URL
  - --json @prepared $URL
  - --json @- $URL < json.txt
---

# `--json`

Sends the specified JSON data in a POST request to the HTTP server. --json
works as a shortcut for passing on these three options:

    --data [arg]
    --header "Content-Type: application/json"
    --header "Accept: application/json"

There is **no verification** that the passed in data is actual JSON or that
the syntax is correct.

If you start the data with the letter @, the rest should be a filename to read
the data from, or a single dash (-) if you want curl to read the data from
stdin. Posting data from a file named 'foobar' would thus be done with --json
@foobar and to instead read the data from stdin, use --json @-.

If this option is used more than once on the same command line, the additional
data pieces are concatenated to the previous before sending.

The headers this option sets can be overridden with --header as usual.
