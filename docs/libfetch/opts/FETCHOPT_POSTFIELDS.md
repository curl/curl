---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_POSTFIELDS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_COPYPOSTFIELDS (3)
  - FETCHOPT_MIMEPOST (3)
  - FETCHOPT_POSTFIELDSIZE (3)
  - FETCHOPT_READFUNCTION (3)
  - FETCHOPT_UPLOAD (3)
Protocol:
  - HTTP
  - MQTT
Added-in: 7.1
---

# NAME

FETCHOPT_POSTFIELDS - data to POST to server

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_POSTFIELDS, char *postdata);
~~~

# DESCRIPTION

Pass a char pointer as parameter, pointing to the data buffer to use in an
HTTP POST operation or an MQTT subscribe. The data must be formatted and
encoded the way you want the server to receive it. libfetch does not convert or
encode it in any way. For example, a web server may assume that this data is
URL encoded.

The data pointed to is NOT copied by the library: as a consequence, it must be
preserved by the calling application until the associated transfer finishes.
This behavior can be changed (so libfetch does copy the data) by instead using
the FETCHOPT_COPYPOSTFIELDS(3) option.

This POST is a normal **application/x-www-form-urlencoded** kind (and libfetch
sets that Content-Type by default when this option is used), which is commonly
used by HTML forms. Change Content-Type with FETCHOPT_HTTPHEADER(3).

You can use fetch_easy_escape(3) to URL encode your data, if
necessary. It returns a pointer to an encoded string that can be passed as
*postdata*.

Using FETCHOPT_POSTFIELDS(3) implies setting FETCHOPT_POST(3) to 1.

If FETCHOPT_POSTFIELDS(3) is explicitly set to NULL then libfetch gets the POST
data from the read callback. To send a zero-length (empty) POST, set
FETCHOPT_POSTFIELDS(3) to an empty string, or set FETCHOPT_POST(3) to 1 and
FETCHOPT_POSTFIELDSIZE(3) to 0.

libfetch assumes this option points to a null-terminated string unless you also
set FETCHOPT_POSTFIELDSIZE(3) to specify the length of the provided data, which
then is strictly required if you want to send off null bytes included in the
data.

Using POST with HTTP 1.1 implies the use of a "Expect: 100-continue" header,
and libfetch adds that header automatically if the POST is either known to be
larger than 1MB or if the expected size is unknown. You can disable this
header with FETCHOPT_HTTPHEADER(3) as usual.

To make **multipart/formdata** posts, check out the
FETCHOPT_MIMEPOST(3) option combined with fetch_mime_init(3).

Using this option multiple times makes the last set pointer override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
/* send an application/x-www-form-urlencoded POST */
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    const char *data = "data to send";

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* size of the POST data if strlen() is not good enough */
    fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDSIZE, 12L);

    /* pass in a pointer to the data - libfetch does not copy */
    fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDS, data);

    fetch_easy_perform(fetch);
  }

  /* send an application/json POST */
  fetch = fetch_easy_init();
  if(fetch) {
    const char *json = "{\"name\": \"daniel\"}";
    struct fetch_slist *slist1 = NULL;
    slist1 = fetch_slist_append(slist1, "Content-Type: application/json");
    slist1 = fetch_slist_append(slist1, "Accept: application/json");

    /* set custom headers */
    fetch_easy_setopt(fetch, FETCHOPT_HTTPHEADER, slist1);

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* pass in a pointer to the data - libfetch does not copy */
    fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDS, json);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
