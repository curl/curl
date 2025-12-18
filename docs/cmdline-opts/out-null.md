---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: out-null
Help: Discard response data into the void
Category: output
Added: 8.16.0
Multi: per-URL
See-also:
  - output
  - remote-name
  - remote-name-all
  - remote-header-name
Example:
  - "https://example.com" --out-null
---

# `--out-null`

Discard all response output of a transfer silently. This is the more
efficient and portable version of

    curl https://host.example -o /dev/null

The transfer is done in full, all data is received and checked, but
the bytes are not written anywhere.
