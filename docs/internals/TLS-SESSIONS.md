<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# TLS Sessions and Tickets

The TLS protocol offers methods of "resuming" a previous "session". A
TLS "session" is a negotiated security context across a connection
(which may be via TCP or UDP or other transports.)

By "resuming", the TLS protocol means that the security context from
before can be fully or partially resurrected when the TLS client presents
the proper crypto stuff to the server. This saves on the amount of
TLS packets that need to be sent back and forth, reducing amount
of data and even latency. In the case of QUIC, resumption may send
application data without having seen any reply from the server, hence
this is named 0-RTT data.

The exact mechanism of session tickets in TLSv1.2 (and earlier) and
TLSv1.3 differs. TLSv1.2 tickets have several weaknesses (that can
be exploited by attackers) which TLSv1.3 then fixed. See
[Session Tickets in the real world](https://words.filippo.io/we-need-to-talk-about-session-tickets/)
for an insight into this topic.

These difference between TLS protocol versions are reflected in curl's
handling of session tickets. More below.

## curl's `ssl_peer_key`

In order to find a ticket from a previous TLS session, curl
needs a name for TLS sessions that uniquely identifies the peer
it talks to.

This name has to reflect also the various TLS parameters that can
be configured in curl for a connection. We do not want to use
a ticket from an different configuration. Example: when setting
the maximum TLS version to 1.2, we do not want to reuse a ticket
we got from a TLSv1.3 session, although we are talking to the
same host.

Internally, we call this name a `ssl_peer_key`. It is a printable
string that carries hostname and port and any non-default TLS
parameters involved in the connection.

Examples:
- `curl.se:443:CA-/etc/ssl/cert.pem:IMPL-GnuTLS/3.8.7` is a peer key for
   a connection to `curl.se:443` using `/etc/ssl/cert.pem` as CA
   trust anchors and GnuTLS/3.8.7 as TLS backend.
- `curl.se:443:TLSVER-6-6:CA-/etc/ssl/cert.pem:IMPL-GnuTLS/3.8.7` is the
   same as the previous, except it is configured to use TLSv1.2 as
   min and max versions.

Different configurations produce different keys which is just what
curl needs when handling SSL session tickets.

One important thing: peer keys do not contain confidential information. If you
configure a client certificate or SRP authentication with username/password,
these are not part of the peer key.

However, peer keys carry the hostnames you use curl for. They *do*
leak the privacy of your communication. We recommend to *not* persist
peer keys for this reason.

**Caveat**: The key may contain filenames or paths. It does not reflect the
*contents* in the filesystem. If you change `/etc/ssl/cert.pem` and reuse a
previous ticket, curl might trust a server which no longer has a root
certificate in the file.


## Session Cache Access

#### Lookups

When a new connection is being established, each SSL connection filter creates
its own peer_key and calls into the cache. The cache then looks for a ticket
with exactly this peer_key. Peer keys between proxy SSL filters and SSL
filters talking through a tunnel differ, as they talk to different peers.

If the connection filter wants to use a client certificate or SRP
authentication, the cache checks those as well. If the cache peer carries
client cert or SRP auth, the connection filter must have those with the same
values (and vice versa).

On a match, the connection filter gets the session ticket and feeds that to
the TLS implementation which, on accepting it, tries to resume it for a
shorter handshake. In addition, the filter gets the ALPN used before and the
amount of 0-RTT data that the server announced to be willing to accept. The
filter can then decide if it wants to attempt 0-RTT or not. (The ALPN is
needed to know if the server speaks the protocol you want to send in 0-RTT. It
makes no sense to send HTTP/2 requests to a server that only knows HTTP/1.1.)

#### Updates

When a new TLS session ticket is received by a filter, it adds it to the
cache using its peer_key and SSL configuration. The cache looks for
a matching entry and, should it find one, adds the ticket for this
peer.

### Put, Take and Return

when a filter accesses the session cache, it *takes*
a ticket from the cache, meaning a returned ticket is removed. The filter
then configures its TLS backend and *returns* the ticket to the cache.

The cache needs to treat tickets from TLSv1.2 and 1.3 differently. 1.2 tickets
should be reused, but 1.3 tickets SHOULD NOT (RFC 8446). The session cache
simply drops 1.3 tickets when they are returned after use, but keeps a 1.2
ticket.

When a ticket is *put* into the cache, there is also a difference. There
can be several 1.3 tickets at the same time, but only a single 1.2 ticket.
TLSv1.2 tickets replace any other. 1.3 tickets accumulate up to a max
amount.

By having a "put/take/return" we reflect the 1.3 use case nicely. Two
concurrent connections do not reuse the same ticket.

## Session Ticket Persistence

#### Privacy and Security

As mentioned above, ssl peer keys are not intended for storage in a file
system. They clearly show which hosts the user talked to. This maybe "just"
privacy relevant, but has security implications as an attacker might find
worthy targets among your peer keys.

Also, we do not recommend to persist TLSv1.2 tickets.

### Salted Hashes

The TLS session cache offers an alternative to storing peer keys:
it provides a salted SHA256 hash of the peer key for import and export.

#### Export

The salt is generated randomly for each peer key on export. The SHA256 makes
sure that the peer key cannot be reversed and that a slightly different key
still produces a different result.

This means an attacker cannot just "grep" a session file for a particular
entry, e.g. if they want to know if you accessed a specific host. They *can*
however compute the SHA256 hashes for all salts in the file and find a
specific entry. They *cannot* find a hostname they do not know. They would
have to brute force by guessing.

#### Import

When session tickets are imported from a file, curl only gets the salted
hashes. The imported tickets belong to an *unknown* peer key.

When a connection filter tries to *take* a session ticket, it passes its peer
key. This peer key initially does not match any tickets in the cache. The
cache then checks all entries with unknown peer keys if the passed key matches
their salted hash. If it does, the peer key is recovered and remembered at the
cache entry.

This is a performance penalty in the order of "unknown" peer keys which
diminishes over time when keys are rediscovered. Note that this also works for
putting a new ticket into the cache: when no present entry matches, a new one
with peer key is created. This peer key then no longer bears the cost of hash
computes.
