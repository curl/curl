c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: fail-early
Help: Fail on first transfer error, do not continue
Added: 7.52.0
Category: curl
Example: --fail-early $URL https://two.example
See-also: fail fail-with-body
Multi: boolean
Scope: global
---
Fail and exit on the first detected transfer error.

When curl is used to do multiple transfers on the command line, it attempts to
operate on each given URL, one by one. By default, it ignores errors if there
are more URLs given and the last URL's success determines the error code curl
returns. So early failures are "hidden" by subsequent successful transfers.

Using this option, curl instead returns an error on the first transfer that
fails, independent of the amount of URLs that are given on the command
line. This way, no transfer failures go undetected by scripts and similar.

This option does not imply --fail, which causes transfers to fail due to the
server's HTTP status code. You can combine the two options, however note --fail
is not global and is therefore contained by --next.
