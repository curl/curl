---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_ssls_import
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SHARE (3)
  - fetch_share_setopt (3)
  - fetch_easy_ssls_export (3)
Protocol:
  - TLS
TLS-backend:
  - GnuTLS
  - OpenSSL
  - BearSSL
  - wolfSSL
  - mbedTLS
Added-in: 8.12.0
---

# NAME

fetch_easy_ssls_export - export SSL sessions

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_ssls_import(FETCH *handle,
                               const char *session_key,
                               const unsigned char *shmac, size_t shmac_len,
                               const unsigned char *sdata, size_t sdata_len);
~~~

# DESCRIPTION

This function imports a previously exported SSL session ticket. **sdata** and
**sdata_len** must always be provided. If **session_key** is **NULL**, then
**shmac** and **shmac_len** must be given as received during the export.
See fetch_easy_ssls_export(3) for a description of those.

Import of session tickets from other fetch versions may fail due to changes
in the handling of **shmac** or **sdata**. A session ticket which has
already expired is silently discarded.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHSHcode sh;
  FETCHSH *share = fetch_share_init();
  FETCHcode rc;
  FETCH *fetch;

  sh = fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_SSL_SESSION);
  if(sh)
    printf("Error: %s\n", fetch_share_strerror(sh));

  fetch = fetch_easy_init();
  if(fetch) {
    unsigned char *shmac, *sdata;
    size_t hlen, slen;

    fetch_easy_setopt(fetch, FETCHOPT_SHARE, share);

    /* read shmac and sdata from storage */
    rc = fetch_easy_ssls_import(fetch, NULL, shmac, hlen, sdata, slen);

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  fetch_share_cleanup(share);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3). If FETCHOPT_ERRORBUFFER(3) was set with fetch_easy_setopt(3)
there can be an error message stored in the error buffer when non-zero is
returned.
