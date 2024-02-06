---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: remove-on-error
Help: Remove output file on errors
Category: curl
Added: 7.83.0
Multi: boolean
See-also:
  - fail
Example:
  - --remove-on-error -o output $URL
---

# `--remove-on-error`

When curl returns an error when told to save output in a local file, this
option removes that saved file before exiting. This prevents curl from
leaving a partial file in the case of an error during transfer.

If the output is not a regular file, this option has no effect.
