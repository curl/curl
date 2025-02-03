---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: libfetch-share
Section: 3
Source: libfetch
See-also:
  - fetch_share_cleanup (3)
  - fetch_share_init (3)
  - fetch_share_setopt (3)
  - libfetch-easy (3)
  - libfetch-errors (3)
  - libfetch-multi (3)
Protocol:
  - All
Added-in: n/a
---

# NAME

libfetch-share - how to use the share interface

# DESCRIPTION

This is an overview on how to use the libfetch share interface in your C
programs. There are specific man pages for each function mentioned in
here.

All functions in the share interface are prefixed with fetch_share.

# OBJECTIVES

The share interface was added to enable sharing of data between fetch handles.

# ONE SET OF DATA - MANY TRANSFERS

You can have multiple easy handles share data between them. Have them update
and use the **same** cookie database, DNS cache, TLS session cache and/or
connection cache. This way, each single transfer takes advantage from data
updates made by the other transfer(s).

# SHARE OBJECT

You create a shared object with fetch_share_init(3). It returns a handle
for a newly created one.

You tell the shared object what data you want it to share by using
fetch_share_setopt(3).

Since you can use this share from multiple threads, and libfetch has no
internal thread synchronization, you must provide mutex callbacks if you are
using this multi-threaded. You set lock and unlock functions with
fetch_share_setopt(3) too.

Then, you make an easy handle to use this share, you set the
FETCHOPT_SHARE(3) option with fetch_easy_setopt(3), and pass in
share handle. You can make any number of easy handles share the same share
handle.

To make an easy handle stop using that particular share, you set
FETCHOPT_SHARE(3) to NULL for that easy handle. To make a handle stop
sharing a particular data, you can FETCHSHOPT_UNSHARE(3) it.

When you are done using the share, make sure that no easy handle is still using
it, and call fetch_share_cleanup(3) on the handle.
