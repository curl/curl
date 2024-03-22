---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PREREQDATA
Section: 3
Source: libcurl
See-also:
  - CURLINFO_PRIMARY_IP (3)
  - CURLINFO_PRIMARY_PORT (3)
  - CURLOPT_PREREQFUNCTION (3)
Protocol:
  - All
---

# NAME

CURLOPT_PREREQDATA - pointer passed to the pre-request callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PREREQDATA, void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* that is untouched by libcurl and passed as the first
argument in the pre-request callback set with CURLOPT_PREREQFUNCTION(3).

# DEFAULT

NULL

# EXAMPLE

~~~c
struct priv {
  void *custom;
};

static int prereq_callback(void *clientp,
                           char *conn_primary_ip,
                           char *conn_local_ip,
                           int conn_primary_port,
                           int conn_local_port)
{
  printf("Connection made to %s:%d\n", conn_primary_ip, conn_primary_port);
  return CURL_PREREQFUNC_OK;
}

int main(void)
{
  struct priv prereq_data;
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_PREREQFUNCTION, prereq_callback);
    curl_easy_setopt(curl, CURLOPT_PREREQDATA, &prereq_data);
    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.80.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
