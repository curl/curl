---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: aws-sigv4-signedheaders
Arg: <list>
Help: AWS V4 signed headers list (semicolon delimited)
Protocols: HTTP
Added: 8.17.0
Category: auth http
Multi: single
See-also:
  - aws-sigv4
  - aws-sigv4-algorithm
  - aws-sigv4-mode
Example:
  - --aws-sigv4-signedheaders "host;x-amz-date" $URL
---

# `--aws-sigv4-signedheaders`

Specify which headers to include in the AWS Signature Version 4 calculation.
The list should be semicolon-delimited header names.

**This option completely overrides the default header selection.** When specified,
only the headers listed are included in the signature calculation.

When this option is not specified, curl automatically includes these headers
in the signature:

- **host** - Always included (added automatically if not present)
- **x-amz-date** (or **x-{provider}-date**) - Always included
- **x-amz-content-sha256** - Included for S3 requests
- **content-type** - Included when request has a body
- **Any custom headers** specified with --header

This option works with both SIGV4 (HMAC-SHA256) and SIGV4A (ECDSA-P256-SHA256)
algorithms.
