---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_FNMATCH_DATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FNMATCH_FUNCTION (3)
  - CURLOPT_WILDCARDMATCH (3)
Protocol:
  - FTP
Added-in: 7.21.0
---

# NAME

CURLOPT_FNMATCH_DATA - pointer passed to the fnmatch callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FNMATCH_DATA,
                          void *pointer);
~~~

# DESCRIPTION

Pass a pointer that is untouched by libcurl and passed as the ptr argument to
the CURLOPT_FNMATCH_FUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
extern int string_match(const char *s1, const char *s2);

struct local_stuff {
  void *custom;
};

static int my_fnmatch(void *clientp,
                      const char *pattern, const char *string)
{
  struct local_stuff *my = clientp;
  printf("my ptr: %p\n", my->custom);

  if(string_match(pattern, string))
    return CURL_FNMATCHFUNC_MATCH;
  else
    return CURL_FNMATCHFUNC_NOMATCH;
}

int main(void)
{
  struct local_stuff local_data;
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://ftp.example.com/file*");
    curl_easy_setopt(curl, CURLOPT_WILDCARDMATCH, 1L);
    curl_easy_setopt(curl, CURLOPT_FNMATCH_FUNCTION, my_fnmatch);
    curl_easy_setopt(curl, CURLOPT_FNMATCH_DATA, &local_data);

    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
