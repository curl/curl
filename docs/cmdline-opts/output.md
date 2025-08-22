---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: output
Arg: <file>
Short: o
Help: Write to file instead of stdout
Category: important output
Added: 4.0
Multi: per-URL
See-also:
  - out-null
  - remote-name
  - remote-name-all
  - remote-header-name
Example:
  - -o file $URL
  - "http://{one,two}.example.com" -o "file_#1.txt"
  - "http://{site,host}.host[1-5].example" -o "#1_#2"
  - -o file $URL -o file2 https://example.net
---

# `--output`

Write output to the given file instead of stdout. If you are using globbing to
fetch multiple documents, you should quote the URL and you can use `#`
followed by a number in the filename. That variable is then replaced with the
current string for the URL being fetched. Like in:

    curl "http://{one,two}.example.com" -o "file_#1.txt"

or use several variables like:

    curl "http://{site,host}.host[1-5].example" -o "#1_#2"

You may use this option as many times as the number of URLs you have. For
example, if you specify two URLs on the same command line, you can use it like
this:

    curl -o aa example.com -o bb example.net

and the order of the -o options and the URLs does not matter, just that the
first -o is for the first URL and so on, so the above command line can also be
written as

    curl example.com example.net -o aa -o bb

See also the --create-dirs option to create the local directories
dynamically. Specifying the output as '-' (a single dash) passes the output to
stdout.

To suppress response bodies, you can redirect output to /dev/null:

    curl example.com -o /dev/null

Or for Windows:

    curl example.com -o nul

Or, even more efficient and portable, use

    curl example.com --out-null

Specify the filename as single minus to force the output to stdout, to
override curl's internal binary output in terminal prevention:

    curl https://example.com/jpeg -o -
