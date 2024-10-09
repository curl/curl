---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tls-earlydata
Help: Allow use of TLSv1.3 early data (0RTT)
Protocols: TLS
Added: 8.11.0
Category: tls
Multi: boolean
See-also:
  - tlsv1.3
  - tls-max
Example:
  - --tls-earlydata $URL
---

# `--tls-earlydata`

Enable the use of TLSv1.3 early data, also known as '0RTT' where possible.
This has security implications for the requests sent that way.

This option is used when curl is built to use GnuTLS.

If a server supports this TLSv1.3 feature, and to what extent, is announced
as part of the TLS "session" sent back to curl. Until curl has seen such
a session in a previous request, early data cannot be used.

When a new connection is initiated with a known TLSv1.3 session, and that
session announced early data support, the first request on this connection is
sent *before* the TLS handshake is complete. While the early data is also
encrypted, it is not protected against replays. An attacker can send
your early data to the server again and the server would accept it.

If your request contacts a public server and only retrieves a file, there
may be no harm in that. If the first request orders a refrigerator
for you, it is probably not a good idea to use early data for it. curl
cannot deduce what the security implications of your requests actually
are and make this decision for you.

**WARNING**: this option has security implications. See above for more
details.
