---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_NTFYDATA
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_NTFYFUNCTION (3)
  - curl_multi_ntfy_disable (3)
  - curl_multi_ntfy_enable (3)
Protocol:
  - All
Added-in: 8.17.0
---

# NAME

CURLMOPT_NTFYDATA - custom pointer passed to the notification callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_NTFYDATA, void *pointer);
~~~

# DESCRIPTION

A data *pointer* to pass to the notification callback set with the
CURLMOPT_NTFYFUNCTION(3) option.

This pointer is not touched by libcurl but is only passed in as the
notification callback's **clientp** argument.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct priv {
  void *ours;
};

static void ntfy_cb(CURLM *multi, unsigned int notification,
                    CURL *easy, void *ntfyp)
{
  struct priv *p = ntfyp;
  printf("my ptr: %p\n", p->ours);
  /* ... */
}

int main(void)
{
  struct priv setup;
  CURLM *multi = curl_multi_init();
  /* ... use socket callback and custom pointer */
  curl_multi_setopt(multi, CURLMOPT_NTFYFUNCTION, ntfy_cb);
  curl_multi_setopt(multi, CURLMOPT_NTFYDATA, &setup);
  curl_multi_ntfy_enable(multi, CURLM_NTFY_INFO_READ);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLM_OK.
