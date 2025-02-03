---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSH_KEYFUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSH_KEYDATA (3)
  - FETCHOPT_SSH_KNOWNHOSTS (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.19.6
---

# NAME

FETCHOPT_SSH_KEYFUNCTION - callback for known host matching logic

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

enum fetch_khstat {
  FETCHKHSTAT_FINE_ADD_TO_FILE,
  FETCHKHSTAT_FINE,
  FETCHKHSTAT_REJECT, /* reject the connection, return an error */
  FETCHKHSTAT_DEFER,  /* do not accept it, but we cannot answer right
                        now. Causes a FETCHE_PEER_FAILED_VERIFICATION error but
                        the connection is left intact */
  FETCHKHSTAT_FINE_REPLACE
};

enum fetch_khmatch {
  FETCHKHMATCH_OK,       /* match */
  FETCHKHMATCH_MISMATCH, /* host found, key mismatch */
  FETCHKHMATCH_MISSING,  /* no matching host/key found */
};

struct fetch_khkey {
  const char *key; /* points to a null-terminated string encoded with
                      base64 if len is zero, otherwise to the "raw"
                      data */
  size_t len;
  enum fetch_khtype keytype;
};

int ssh_keycallback(FETCH *easy,
                    const struct fetch_khkey *knownkey,
                    const struct fetch_khkey *foundkey,
                    enum fetch_khmatch match,
                    void *clientp);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSH_KEYFUNCTION,
                          ssh_keycallback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

It gets called when the known_host matching has been done, to allow the
application to act and decide for libfetch how to proceed. The callback is only
called if FETCHOPT_SSH_KNOWNHOSTS(3) is also set.

This callback function gets passed the fetch handle, the key from the
known_hosts file *knownkey*, the key from the remote site *foundkey*, info
from libfetch on the matching status and a custom pointer (set with
FETCHOPT_SSH_KEYDATA(3)). It MUST return one of the following return codes to
tell libfetch how to act:

## FETCHKHSTAT_FINE_REPLACE

The new host+key is accepted and libfetch replaces the old host+key into the
known_hosts file before continuing with the connection. This also adds the new
host+key combo to the known_host pool kept in memory if it was not already
present there. The adding of data to the file is done by completely replacing
the file with a new copy, so the permissions of the file must allow
this. (Added in 7.73.0)

## FETCHKHSTAT_FINE_ADD_TO_FILE

The host+key is accepted and libfetch appends it to the known_hosts file before
continuing with the connection. This also adds the host+key combo to the
known_host pool kept in memory if it was not already present there. The adding
of data to the file is done by completely replacing the file with a new copy,
so the permissions of the file must allow this.

## FETCHKHSTAT_FINE

The host+key is accepted libfetch continues with the connection. This also adds
the host+key combo to the known_host pool kept in memory if it was not already
present there.

## FETCHKHSTAT_REJECT

The host+key is rejected. libfetch denies the connection to continue and it is
closed.

## FETCHKHSTAT_DEFER

The host+key is rejected, but the SSH connection is asked to be kept alive.
This feature could be used when the app wants to return and act on the
host+key situation and then retry without needing the overhead of setting it
up from scratch again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct mine {
  void *custom;
};

static int keycb(FETCH *easy,
                 const struct fetch_khkey *knownkey,
                 const struct fetch_khkey *foundkey,
                 enum fetch_khmatch match,
                 void *clientp)
{
  /* 'clientp' points to the callback_data struct */
  /* investigate the situation and return the correct value */
  return FETCHKHSTAT_FINE_ADD_TO_FILE;
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    struct mine callback_data;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "sftp://example.com/thisfile.txt");
    fetch_easy_setopt(fetch, FETCHOPT_SSH_KEYFUNCTION, keycb);
    fetch_easy_setopt(fetch, FETCHOPT_SSH_KEYDATA, &callback_data);
    fetch_easy_setopt(fetch, FETCHOPT_SSH_KNOWNHOSTS, "/home/user/known_hosts");

    fetch_easy_perform(fetch);
}
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
