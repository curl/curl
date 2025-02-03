---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSH_HOSTKEYFUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSH_HOSTKEYDATA (3)
  - FETCHOPT_SSH_KNOWNHOSTS (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.84.0
---

# NAME

FETCHOPT_SSH_HOSTKEYFUNCTION - callback to check host key

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

int keycallback(void *clientp,
                int keytype,
                const char *key,
                size_t keylen);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSH_HOSTKEYFUNCTION,
                          keycallback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above. It overrides FETCHOPT_SSH_KNOWNHOSTS(3).

This callback gets called when the verification of the SSH host key is needed.

**key** is **keylen** bytes long and is the key to check. **keytype**
says what type it is, from the **FETCHKHTYPE_*** series in the
**fetch_khtype** enum.

**clientp** is a custom pointer set with FETCHOPT_SSH_HOSTKEYDATA(3).

The callback MUST return one of the following return codes to tell libfetch how
to act:

## FETCHKHMATCH_OK

The host key is accepted, the connection should continue.

## FETCHKHMATCH_MISMATCH

the host key is rejected, the connection is canceled.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct mine {
  void *custom;
};

int hostkeycb(void *clientp,    /* passed with FETCHOPT_SSH_HOSTKEYDATA */
              int keytype,      /* FETCHKHTYPE */
              const char *key,  /* host key to check */
              size_t keylen)    /* length of the key */
{
  /* 'clientp' points to the callback_data struct */
  /* investigate the situation and return the correct value */
  return FETCHKHMATCH_OK;
}
int main(void)
{
  struct mine callback_data;
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "sftp://example.com/thisfile.txt");
    fetch_easy_setopt(fetch, FETCHOPT_SSH_HOSTKEYFUNCTION, hostkeycb);
    fetch_easy_setopt(fetch, FETCHOPT_SSH_HOSTKEYDATA, &callback_data);

    fetch_easy_perform(fetch);
  }
}
~~~

# NOTES

Work only with the libssh2 backend.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
