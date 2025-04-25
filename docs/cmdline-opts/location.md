---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: location
Short: L
Help: Follow redirects
Protocols: HTTP
Category: http
Added: 4.9
Multi: boolean
See-also:
  - resolve
  - alt-svc
  - follow
Example:
  - -L $URL
---

# `--location`

If the server reports that the requested page has moved to a different
location (indicated with a Location: header and a 3XX response code), this
option makes curl redo the request to the new place. If used together with
--show-headers or --head, headers from all requested pages are shown.

When authentication is used, or when sending a cookie with `-H Cookie:`, curl
only sends its credentials to the initial host. If a redirect takes curl to a
different host, it does not get the credentials passed on. See
--location-trusted on how to change this.

Limit the amount of redirects to follow by using the --max-redirs option.

When curl follows a redirect and if the request is a POST, it sends the
following request with a GET if the HTTP response was 301, 302, or 303. If the
response code was any other 3xx code, curl resends the following request using
the same unmodified method.

You can tell curl to not change POST requests to GET after a 30x response by
using the dedicated options for that: --post301, --post302 and --post303.

The method set with --request overrides the method curl would otherwise select
to use.
