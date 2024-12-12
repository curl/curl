<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# TLS Session Handling

The TLS protocol offers what is commonly named "sessions" to allow
for faster resumptions and even sending of 0-RTT data when opening
a connection to a previously visited server. The exact mechanism
varies a bit between TLSv1.2 and TLSv1.3.

## Curl's `peer_key`

To allow reusing these sessions, libcurl provides the capability
to cache up to a fixed number of them. This can be achieved by
configuring a curl share instance.

The TLS session cache uses a `peer_key` to identify for which server
and settings a session is about. This is a printable string, created
as described below.

#### peer name

Such a key always starts with `<hostname>:<port>` of the server
curl talks to. Because we do not want to use a TLS session for
another server (even if the server is not malicious, it comes at
a performance penalty).

If the connection is not using TCP, curl appends the transport used
to the key. `curl.se:443:QUIC` would be the start of a peer_key when
talking to curl.se via QUIC. Another transport is `UNIX` when talking
over a socket.

#### peer verification

Next in the key come indications when the transfer's TLS settings
vary from the defaults. `:NO-VRFY-PEER` is appended when the peer
verification is configured off. `:NO-VRFY-HOST` when hostname verification
is off. The reason for these is that a successfully resumed TLS session
will not longer verify the certificate. Mixing sessions for these TLS
settings then would not give the results as intended.

Next we append `:VRFY-STATUS` to the peek_key if that is enabled. We
do not want to reuse session in connections that want to check revocation
information that did not do this before.

#### connect-to 

If curl was configured with `--connect-to` parameters and either peer or
host verification was off, the `connect-to` host and port are appended
as well. This is because when the peer certificate had been fully verified
before, it does not matter via which address or SSH tunnel curl is talking
to it (more on trust aspects below).

Furthermore we make the configured TLS versions, options, ciphers and curve
settings part of the peer_key when they are not default. If a transfer
wants TLSv1.3, it should not reused a TLSv1.2 session.

### trust anchors

All certificate verification relies on the trust anchors that are used.
These can be configured in various ways as `CAfile`, `CApath`, `IssuerCert`,
`CertBlob`, `CAInfoBlob` or `IssuerBlob`. When they are set, the are added
to the peer_key in the following ways:

 * file and path names are converted to absolute paths. This makes the
   peer_key independent of the current working directory.
 * Blobs are hashed using SHA256 and appended in hexadecimal notation.

This makes the peer_key unique for the trust anchors you have configured.
However, when the files or paths configured change their *content*, this
may mess peer verification up. Example: you remove a trust anchor from
a `--cacert` file. Connections reusing a TLS session from a peer no
longer trusted could then still be successful for a while.

#### client certificate and SRP username/password

Client certificates and SRP username/password are **not** added to the
peer key. However, when they are used, `:CCERT` or `:SRP-AUTH` is added
to the key. This prevents mixing of TLS sessions between connections
that differ here. (There are more checks in the session cache that
prevent mixup of different client certificates and user info. See below.)

Finally, the peer_key gets the TLS implementation name and version
added as `:IMPL-<name>/<version>`. This prevents giving session data to
TLS implementations that might choke on them.

## TLS Session Cache Access

#### Lookups

When a new connection is being established, each SSL connection filter creates
its own peer_key and calls into the cache. The cache then looks for an entry
with exactly this peer_key. Peer keys between proxy SSL filters and SSL
filters talking through a tunnel will be different, as they talk to different
peers.

If the connection filter wants to use a client certificate or SRP
authentication, the entry also needs to carry the same or is not a match.
This works both ways. If the entry carries client cert or SRP auth, a
connection filter which does not have those will not match either.

On a match, the connection filter gets the session data and feeds that
to the TLS implementation which, on accepting it, will try to resume it
for a shorter handshake. In addition, the filter gets the ALPN used
before and the amount of 0-RTT data that the server announced to be
willing to accept. The filter can then decide if it wants to attempt
0-RTT or not.

#### Updates

When a new TLS session is received by a filter, it adds it to the
cache using its peer_key and SSL configuration. The cache looks for
a matching entry and, should it find one, replaces the entries data
with the new session.

Otherwise, it looks for a free entry or purges the oldest or an expired
entry to make room.

## TLS Session Persistence

Peer key and other information work will when only in memory. When session
data should be stored more permanent, issues with security and privacy
have to be considered.

libcurl will not offer the export of TLS session data that has been
obtained useing a client certificat or SRP authentication. An attacker
could use that session to impersonate a user at a server.

#### salted hashes

TLS session without such will be exportable. For privacy reasons, we
do **not** recommend storing peer_keys in plain form. Instead, libcurl
offers salted hashes of peer keys for export and re-import. This means
that an attacker cannot easily find out to which hosts a user has made
connections. They would have to guess and brute-force attempt the existing
salt and hashes to find a match.

Note however, that if someone has a curl session file and wants to check
if a connection to `google.com` has been made, the salted hash provides
no real obstacle. In fact, this is done by the session cache for imported
sessions.

When sessions are imported from a file, they will only have the salted
hashes, but no peer keys. When a connection does a lookup with a peer key,
the cache will find no immediate match.

Instead, it will used the passed peer key and the salt of an entry
to compute the hash again and see if it matches. If an entry matches,
there is a high likelyhood that the session has been made using the
same peer key.

The matching peer key is then remembered at the matched cache entry. No
future lookups will need to check against the salted hash again.
