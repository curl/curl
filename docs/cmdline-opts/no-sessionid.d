c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: no-sessionid
Help: Disable SSL session-ID reusing
Protocols: TLS
Added: 7.16.0
Category: tls
Example: --no-sessionid $URL
See-also: insecure
---
Disable curl's use of SSL session-ID caching. By default all transfers are
done using the cache. Note that while nothing should ever get hurt by
attempting to reuse SSL session-IDs, there seem to be broken SSL
implementations in the wild that may require you to disable this in order for
you to succeed.

Note that this is the negated option name documented. You can thus use
--sessionid to enforce session-ID caching.
