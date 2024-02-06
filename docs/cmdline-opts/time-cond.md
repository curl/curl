---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: time-cond
Short: z
Arg: <time>
Help: Transfer based on a time condition
Protocols: HTTP FTP
Category: http ftp
Added: 5.8
Multi: single
See-also:
  - etag-compare
  - remote-time
Example:
  - -z "Wed 01 Sep 2021 12:18:00" $URL
  - -z "-Wed 01 Sep 2021 12:18:00" $URL
  - -z file $URL
---

# `--time-cond`

Request a file that has been modified later than the given time and date, or
one that has been modified before that time. The date expression can be all
sorts of date strings or if it does not match any internal ones, it is treated
as a filename and curl tries to get the modification date (mtime) from that
file instead. See the *curl_getdate(3)* man pages for date expression details.

Start the date expression with a dash (-) to make it request for a document
that is older than the given date/time, default is a document that is newer
than the specified date/time.

If provided a non-existing file, curl outputs a warning about that fact and
proceeds to do the transfer without a time condition.
