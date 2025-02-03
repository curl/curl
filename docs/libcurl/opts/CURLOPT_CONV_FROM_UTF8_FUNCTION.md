---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_CONV_FROM_UTF8_FUNCTION
Section: 3
Source: libfetch
Protocol:
  - All
See-also:
  - FETCHOPT_CONV_FROM_NETWORK_FUNCTION (3)
  - FETCHOPT_CONV_TO_NETWORK_FUNCTION (3)
Added-in: 7.15.4
---

# NAME

FETCHOPT_CONV_FROM_UTF8_FUNCTION - convert data from UTF8 to host encoding

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode conv_callback(char *ptr, size_t length);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_CONV_FROM_UTF8_FUNCTION,
                          conv_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

Applies to non-ASCII platforms. fetch_version_info(3) returns the
FETCH_VERSION_CONV feature bit set if this option is provided.

The data to be converted is in a buffer pointed to by the *ptr* parameter.
The amount of data to convert is indicated by the *length* parameter. The
converted data overlays the input data in the buffer pointed to by the ptr
parameter. *FETCHE_OK* must be returned upon successful conversion. A
FETCHcode return value defined by fetch.h, such as *FETCHE_CONV_FAILED*,
should be returned if an error was encountered.

FETCHOPT_CONV_FROM_UTF8_FUNCTION(3) converts to host encoding from UTF8
encoding. It is required only for SSL processing.

If you set a callback pointer to NULL, or do not set it at all, the built-in
libfetch iconv functions are used. If HAVE_ICONV was not defined when libfetch
was built, and no callback has been established, the conversion returns the
FETCHE_CONV_REQD error code.

If HAVE_ICONV is defined, FETCH_ICONV_CODESET_OF_HOST must also be defined.
For example:
~~~c
 #define FETCH_ICONV_CODESET_OF_HOST "IBM-1047"
~~~

The iconv code in libfetch defaults the network and UTF8 codeset names as
follows:
~~~c
#define FETCH_ICONV_CODESET_OF_NETWORK "ISO8859-1"

#define FETCH_ICONV_CODESET_FOR_UTF8   "UTF-8"
~~~

You need to override these definitions if they are different on your system.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
static FETCHcode my_conv_from_utf8_to_ebcdic(char *buffer, size_t length)
{
  int rc = 0;
  /* in-place convert 'buffer' from UTF-8 to EBCDIC */
  if(rc == 0) {
    /* success */
    return FETCHE_OK;
  }
  else {
    return FETCHE_CONV_FAILED;
  }
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  fetch_easy_setopt(fetch, FETCHOPT_CONV_FROM_UTF8_FUNCTION,
                   my_conv_from_utf8_to_ebcdic);
}
~~~

# DEPRECATED

Not available and deprecated since 7.82.0.

Available only if **FETCH_DOES_CONVERSIONS** was defined when libfetch was
built.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
