---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_slist_free_all
Section: 3
Source: libcurl
See-also:
  - curl_slist_append (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

curl_slist_free_all - free an entire curl_slist list

# SYNOPSIS

~~~c
#include <curl/curl.h>

void curl_slist_free_all(struct curl_slist *list);
~~~

# DESCRIPTION

curl_slist_free_all() removes all traces of a previously built curl_slist
linked list.

Passing in a NULL pointer in *list* makes this function return immediately
with no action.

Any use of the **list** after this function has been called and have returned,
is illegal.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *handle;
  struct curl_slist *slist = NULL;

  slist = curl_slist_append(slist, "X-libcurl: coolness");

  if(!slist)
    return -1;

  curl_easy_setopt(handle, CURLOPT_HTTPHEADER, slist);

  curl_easy_perform(handle);

  curl_slist_free_all(slist); /* free the list again */
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Nothing.
