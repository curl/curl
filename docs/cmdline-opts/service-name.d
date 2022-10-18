c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: service-name
Help: SPNEGO service name
Arg: <name>
Added: 7.43.0
Category: misc
Example: --service-name sockd/server $URL
See-also: negotiate proxy-service-name
Multi: single
---
This option allows you to change the service name for SPNEGO.

Examples: --negotiate --service-name sockd would use sockd/server-name.
