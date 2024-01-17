---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_CONV_FROM_UTF8_FUNCTION
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CONV_FROM_NETWORK_FUNCTION (3)
  - CURLOPT_CONV_TO_NETWORK_FUNCTION (3)
---

# NAME

CURLOPT_CONV_FROM_UTF8_FUNCTION - convert data from UTF8 to host encoding

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode conv_callback(char *ptr, size_t length);

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_CONV_FROM_UTF8_FUNCTION,
                          conv_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

Applies to non-ASCII platforms. curl_version_info(3) returns the
CURL_VERSION_CONV feature bit set if this option is provided.

The data to be converted is in a buffer pointed to by the *ptr* parameter.
The amount of data to convert is indicated by the *length* parameter. The
converted data overlays the input data in the buffer pointed to by the ptr
parameter. *CURLE_OK* must be returned upon successful conversion. A
CURLcode return value defined by curl.h, such as *CURLE_CONV_FAILED*,
should be returned if an error was encountered.

CURLOPT_CONV_FROM_UTF8_FUNCTION(3) converts to host encoding from UTF8
encoding. It is required only for SSL processing.

If you set a callback pointer to NULL, or do not set it at all, the built-in
libcurl iconv functions are used. If HAVE_ICONV was not defined when libcurl
was built, and no callback has been established, the conversion returns the
CURLE_CONV_REQD error code.

If HAVE_ICONV is defined, CURL_ICONV_CODESET_OF_HOST must also be defined.
For example:
~~~c
 #define CURL_ICONV_CODESET_OF_HOST "IBM-1047"
~~~

The iconv code in libcurl defaults the network and UTF8 codeset names as
follows:
~~~c
#define CURL_ICONV_CODESET_OF_NETWORK "ISO8859-1"

#define CURL_ICONV_CODESET_FOR_UTF8   "UTF-8"
~~~

You need to override these definitions if they are different on your system.

# DEFAULT

NULL

# PROTOCOLS

TLS-based protocols.

# EXAMPLE

~~~c
static CURLcode my_conv_from_utf8_to_ebcdic(char *buffer, size_t length)
{
  int rc = 0;
  /* in-place convert 'buffer' from UTF-8 to EBCDIC */
  if(rc == 0) {
    /* success */
    return CURLE_OK;
  }
  else {
    return CURLE_CONV_FAILED;
  }
}

int main(void)
{
  CURL *curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_CONV_FROM_UTF8_FUNCTION,
                   my_conv_from_utf8_to_ebcdic);
}
~~~

# AVAILABILITY

Not available and deprecated since 7.82.0.

Available only if **CURL_DOES_CONVERSIONS** was defined when libcurl was
built.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
