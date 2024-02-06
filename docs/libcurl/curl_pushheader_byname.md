---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: curl_pushheader_byname
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_PUSHFUNCTION (3)
  - curl_pushheader_bynum (3)
---

# NAME

curl_pushheader_byname - get a push header by name

# SYNOPSIS

~~~c
#include <curl/curl.h>

char *curl_pushheader_byname(struct curl_pushheaders *h, const char *name);
~~~

# DESCRIPTION

This is a function that is only functional within a
CURLMOPT_PUSHFUNCTION(3) callback. It makes no sense to try to use it
elsewhere and it has no function then.

It returns the value for the given header field name (or NULL) for the
incoming server push request. This is a shortcut so that the application does
not have to loop through all headers to find the one it is interested in. The
data this function points to is freed when this callback returns. If more than
one header field use the same name, this returns only the first one.

# EXAMPLE

~~~c
#include <string.h> /* for strncmp */

static int push_cb(CURL *parent,
                   CURL *easy,
                   size_t num_headers,
                   struct curl_pushheaders *headers,
                   void *clientp)
{
  char *headp;
  int *transfers = (int *)clientp;
  FILE *out;
  headp = curl_pushheader_byname(headers, ":path");
  if(headp && !strncmp(headp, "/push-", 6)) {
    fprintf(stderr, "The PATH is %s\n", headp);

    /* save the push here */
    out = fopen("pushed-stream", "wb");

    /* write to this file */
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, out);

    (*transfers)++; /* one more */

    return CURL_PUSH_OK;
  }
  return CURL_PUSH_DENY;
}

int main(void)
{
  int counter;
  CURLM *multi = curl_multi_init();
  curl_multi_setopt(multi, CURLMOPT_PUSHFUNCTION, push_cb);
  curl_multi_setopt(multi, CURLMOPT_PUSHDATA, &counter);
}
~~~

# AVAILABILITY

Added in 7.44.0

# RETURN VALUE

Returns a pointer to the header field content or NULL.
