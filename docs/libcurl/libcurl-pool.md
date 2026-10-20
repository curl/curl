---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: libcurl-pool
Section: 3
Source: libcurl
See-also:
  - libcurl-security (3)
Protocol:
  - All
Added-in: n/a
---
# NAME

libcurl-pool - connection pool and TLS session considerations

# Connnection pools

libcurl features a connection pool that allows it to reuse connections held
alive since a previous transfer, instead of creating new ones. It is much
faster then reconnecting.

# TLS sessions

libcurl also features a TLS session cache, which allows it to resume a
previous TLS session then it reconnects to a server it previously communicated
with. It is much faster then redoing the full TLS handshake.

# Multi-tenant use

While connection reuse takes several properties of a new transfer into
account, there are limits.

If a libcurl application is multi-tenant, having transfers across tenants use
a single common connection pool is not a good idea. The same limitations apply
to TLS trust settings.

If you change CA options in the handle while there are live connections in the
pool or TLS sessions in the cache, libcurl does a best effort to match desires
to connections but there are limits. Changing the content of CA files is for
example not detected and use of CURLOPT_SSL_CTX_FUNCTION makes it impossible
to know what magic is done out of libcurl's sight.

If a TLS based connection has been accepted, used and allowed into the pool,
and the TLS sesion into the session cache, libcurl might later reuse an
existing connection or TLS session again if even it would not accept that
server for a fresh new transfer because of changed CA related options in the
handle.

The flexibility of libcurl's API has many advantage, but it requires care by
the application. If you have a mix of credentials and trust settings, it is
your task to verify that a shared connection pool works as you need it.

Do not use a shared connection pool for transfers crossing trust boundaries.

Do not re-use an easy handle for different tenants.
