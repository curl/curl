---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PREREQFUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_PRIMARY_IP (3)
  - FETCHINFO_PRIMARY_PORT (3)
  - FETCHOPT_PREREQDATA (3)
Protocol:
  - All
Added-in: 7.80.0
---

# NAME

FETCHOPT_PREREQFUNCTION - user callback called when a connection has been
established, but before a request has been made.

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

/* These are the return codes for the pre-request callback. */
#define FETCH_PREREQFUNC_OK 0
#define FETCH_PREREQFUNC_ABORT 1 /* fail the entire transfer */

int prereq_callback(void *clientp,
                    char *conn_primary_ip,
                    char *conn_local_ip,
                    int conn_primary_port,
                    int conn_local_port);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PREREQFUNCTION, prereq_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This function gets called by libfetch after a connection has been established
or a connection has been reused (including any SSL handshaking), but before any
request is actually made on the connection. For example, for HTTP, this
callback is called once a connection has been established to the server, but
before a GET/HEAD/POST/etc request has been sent.

This function may be called multiple times if redirections are enabled and are
being followed (see FETCHOPT_FOLLOWLOCATION(3)).

The callback function must return *FETCH_PREREQFUNC_OK* on success, or
*FETCH_PREREQFUNC_ABORT* to cause the transfer to fail with result
*FETCHE_ABORTED_BY_CALLBACK*.

This function is passed the following arguments:

## `conn_primary_ip`

A null-terminated pointer to a C string containing the primary IP of the
remote server established with this connection. For FTP, this is the IP for
the control connection. IPv6 addresses are represented without surrounding
brackets.

## `conn_local_ip`

A null-terminated pointer to a C string containing the originating IP for this
connection. IPv6 addresses are represented without surrounding brackets.

## `conn_primary_port`

The primary port number on the remote server established with this connection.
For FTP, this is the port for the control connection. This can be a TCP or a
UDP port number depending on the protocol.

## `conn_local_port`

The originating port number for this connection. This can be a TCP or a UDP
port number depending on the protocol.

## `clientp`

The pointer you set with FETCHOPT_PREREQDATA(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct priv {
  void *custom;
};

static int prereq_callback(void *clientp,
                           char *conn_primary_ip,
                           char *conn_local_ip,
                           int conn_primary_port,
                           int conn_local_port)
{
  printf("Connection made to %s:%d\n", conn_primary_ip, conn_primary_port);
  return FETCH_PREREQFUNC_OK;
}

int main(void)
{
  struct priv prereq_data;
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_PREREQFUNCTION, prereq_callback);
    fetch_easy_setopt(fetch, FETCHOPT_PREREQDATA, &prereq_data);
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
