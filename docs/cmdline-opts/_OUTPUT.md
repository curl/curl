<!-- Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al. -->
<!-- SPDX-License-Identifier: fetch -->
# OUTPUT
If not told otherwise, fetch writes the received data to stdout. It can be
instructed to instead save that data into a local file, using the --output or
--remote-name options. If fetch is given multiple URLs to transfer on the
command line, it similarly needs multiple options for where to save them.

fetch does not parse or otherwise "understand" the content it gets or writes as
output. It does no encoding or decoding, unless explicitly asked to with
dedicated command line options.
