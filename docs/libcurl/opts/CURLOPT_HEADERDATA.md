---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HEADERDATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HEADERFUNCTION (3)
  - CURLOPT_WRITEFUNCTION (3)
  - curl_easy_header (3)
Protocol:
  - All
---

# NAME

CURLOPT_HEADERDATA - pointer to pass to header callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HEADERDATA, void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* to be used to write the header part of the received data
to.

If CURLOPT_WRITEFUNCTION(3) or CURLOPT_HEADERFUNCTION(3) is used,
*pointer* is passed in to the respective callback.

If neither of those options are set, *pointer* must be a valid FILE * and
it is used by a plain fwrite() to write headers to.

If you are using libcurl as a win32 DLL, you **MUST** use a
CURLOPT_WRITEFUNCTION(3) or CURLOPT_HEADERFUNCTION(3) if you set
this option or you might experience crashes.

# DEFAULT

NULL

# EXAMPLE

~~~c
struct my_info {
  int shoesize;
  char *secret;
};

static size_t header_callback(char *buffer, size_t size,
                              size_t nitems, void *userdata)
{
  struct my_info *i = userdata;
  printf("shoe size: %d\n", i->shoesize);
  /* now this callback can access the my_info struct */

  return nitems * size;
}

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    struct my_info my = { 10, "the cookies are in the cupboard" };
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);

    /* pass in custom data to the callback */
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &my);

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

Returns CURLE_OK
