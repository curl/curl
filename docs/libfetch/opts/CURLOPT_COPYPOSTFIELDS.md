---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_COPYPOSTFIELDS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_MIMEPOST (3)
  - FETCHOPT_POSTFIELDS (3)
  - FETCHOPT_POSTFIELDSIZE (3)
  - FETCHOPT_UPLOAD (3)
Protocol:
  - HTTP
Added-in: 7.17.1
---

# NAME

FETCHOPT_COPYPOSTFIELDS - have libfetch copy data to POST

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_COPYPOSTFIELDS, char *data);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should be the full *data* to post in a
HTTP POST operation. It behaves as the FETCHOPT_POSTFIELDS(3) option, but the
original data is instead copied by the library, allowing the application to
overwrite the original data after setting this option.

Because data is copied, care must be taken when using this option in
conjunction with FETCHOPT_POSTFIELDSIZE(3) or FETCHOPT_POSTFIELDSIZE_LARGE(3).
If the size has not been set prior to FETCHOPT_COPYPOSTFIELDS(3), the data is
assumed to be a null-terminated string; else the stored size informs the
library about the byte count to copy. In any case, the size must not be
changed after FETCHOPT_COPYPOSTFIELDS(3), unless another FETCHOPT_POSTFIELDS(3)
or FETCHOPT_COPYPOSTFIELDS(3) option is set.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    char local_buffer[1024]="data to send";
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* size of the data to copy from the buffer and send in the request */
    fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDSIZE, 12L);

    /* send data from the local stack */
    fetch_easy_setopt(fetch, FETCHOPT_COPYPOSTFIELDS, local_buffer);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
