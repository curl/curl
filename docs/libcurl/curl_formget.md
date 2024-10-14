---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_formget
Section: 3
Source: libcurl
See-also:
  - curl_formadd (3)
  - curl_mime_init (3)
Protocol:
  - HTTP
Added-in: 7.15.5
---

# NAME

curl_formget - serialize a multipart form POST chain

# SYNOPSIS

~~~c
#include <curl/curl.h>

int curl_formget(struct curl_httppost * form, void *userp,
                 curl_formget_callback append);
~~~

# DESCRIPTION

The form API (including this function) is deprecated since libcurl 7.56.0.

curl_formget() serializes data previously built with curl_formadd(3). It
accepts a void pointer as second argument named *userp* which is passed as the
first argument to the curl_formget_callback function.

~~~c
 typedef size_t (*curl_formget_callback)(void *userp, const char *buf,
                                         size_t len);"
~~~

The curl_formget_callback is invoked for each part of the HTTP POST chain. The
character buffer passed to the callback must not be freed. The callback should
return the buffer length passed to it on success.

If the **CURLFORM_STREAM** option is used in the formpost, it prevents
curl_formget(3) from working until you have performed the actual HTTP request.
This, because first then does libcurl known which actual read callback to use.

# %PROTOCOLS%

# EXAMPLE

~~~c
size_t print_httppost_callback(void *arg, const char *buf, size_t len)
{
  fwrite(buf, len, 1, stdout);
  (*(size_t *) arg) += len;
  return len;
}

size_t print_httppost(struct curl_httppost *post)
{
  size_t total_size = 0;
  if(curl_formget(post, &total_size, print_httppost_callback)) {
    return (size_t) -1;
  }
  return total_size;
}
~~~

# %AVAILABILITY%

# RETURN VALUE

0 means everything was OK, non-zero means an error occurred
