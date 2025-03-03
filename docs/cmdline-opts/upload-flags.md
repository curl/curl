---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: upload-flags
Arg: <flags>
Help: Specify additional upload behavior
Category: curl output
Added: 8.13.0
Multi: single
See-also:
  - upload-file
Example:
  - --upload-flags Flagged,!Seen --upload-file local/dir/file $URL
---

# `--upload-flags`

Specify additional behavior to apply to uploaded files. Flags are
specified as either a single flag value or a comma-separated list
of flag values. Flag values may be negated by prepending them with
a '!' character. Currently the following case-sensitive flag values
are accepted: Answered, Deleted, Draft, Flagged, and Seen. The
currently-accepted flag values are used to set flags on IMAP uploads.
