---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_pushheader_bynum
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_PUSHFUNCTION (3)
  - curl_pushheader_byname (3)
Protocol:
  - HTTP
---

# NAME

curl_pushheader_bynum - get a push header by index

# SYNOPSIS

~~~c
#include <curl/curl.h>

char *curl_pushheader_bynum(struct curl_pushheaders *h, size_t num);
~~~

# DESCRIPTION

This is a function that is only functional within a
CURLMOPT_PUSHFUNCTION(3) callback. It makes no sense to try to use it
elsewhere and it has no function then.

It returns the value for the header field at the given index **num**, for
the incoming server push request or NULL. The data pointed to is freed by
libcurl when this callback returns. The returned pointer points to a
"name:value" string that gets freed when this callback returns.

# EXAMPLE

~~~c
/* output all the incoming push request headers */
static int push_cb(CURL *parent,
                   CURL *easy,
                   size_t num_headers,
                   struct curl_pushheaders *headers,
                   void *clientp)
{
  int i = 0;
  char *field;
  do {
     field = curl_pushheader_bynum(headers, i);
     if(field)
       fprintf(stderr, "Push header: %s\n", field);
     i++;
  } while(field);
  return CURL_PUSH_OK; /* permission granted */
}

int main(void)
{
  CURLM *multi = curl_multi_init();
  curl_multi_setopt(multi, CURLMOPT_PUSHFUNCTION, push_cb);
}
~~~

# AVAILABILITY

Added in 7.44.0

# RETURN VALUE

Returns a pointer to the header field content or NULL.
