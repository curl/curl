---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: upload-file
Short: T
Arg: <file>
Help: Transfer local FILE to destination
Category: important upload
Added: 4.0
Multi: per-URL
See-also:
  - get
  - head
  - request
  - data
Example:
  - -T file $URL
  - -T "img[1-1000].png" ftp://ftp.example.com/
  - --upload-file "{file1,file2}" $URL
  - -T file -T file2 $URL $URL
---

# `--upload-file`

Upload the specified local file to the remote URL.

If there is no file part in the specified URL, curl appends the local file
name to the end of the URL before the operation starts. You must use a
trailing slash (/) on the last directory to prove to curl that there is no
filename or curl thinks that your last directory name is the remote filename
to use.

When putting the local filename at the end of the URL, curl ignores what is on
the left side of any slash (/) or backslash (\\) used in the filename and only
appends what is on the right side of the rightmost such character.

Use the filename `-` (a single dash) to use stdin instead of a given file.
Alternately, the filename `.` (a single period) may be specified instead of
`-` to use stdin in non-blocking mode to allow reading server output while
stdin is being uploaded.

If this option is used with an HTTP(S) URL, the PUT method is used.

You can specify one --upload-file for each URL on the command line. Each
--upload-file + URL pair specifies what to upload and to where. curl also
supports globbing of the --upload-file argument, meaning that you can upload
multiple files to a single URL by using the same URL globbing style supported
in the URL.

When uploading to an SMTP server: the uploaded data is assumed to be RFC 5322
formatted. It has to feature the necessary set of headers and mail body
formatted correctly by the user as curl does not transcode nor encode it
further in any way.
