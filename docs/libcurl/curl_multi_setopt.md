---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_multi_setopt
Section: 3
Source: libcurl
See-also:
  - curl_multi_cleanup (3)
  - curl_multi_info_read (3)
  - curl_multi_init (3)
  - curl_multi_socket (3)
Protocol:
  - All
---

# NAME

curl_multi_setopt - set options for a curl multi handle

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *multi_handle, CURLMoption option, parameter);
~~~

# DESCRIPTION

curl_multi_setopt(3) is used to tell a libcurl multi handle how to
behave. By using the appropriate options to curl_multi_setopt(3), you
can change libcurl's behavior when using that multi handle. All options are
set with the *option* followed by the *parameter*. That parameter can
be a **long**, a **function pointer**, an **object pointer** or a
**curl_off_t** type, depending on what the specific option expects. Read
this manual carefully as bad input values may cause libcurl to behave
badly. You can only set one option in each function call.

# OPTIONS

## CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE

See CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE(3)

## CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE

See CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE(3)

## CURLMOPT_MAX_HOST_CONNECTIONS

See CURLMOPT_MAX_HOST_CONNECTIONS(3)

## CURLMOPT_MAX_PIPELINE_LENGTH

See CURLMOPT_MAX_PIPELINE_LENGTH(3)

## CURLMOPT_MAX_TOTAL_CONNECTIONS

See CURLMOPT_MAX_TOTAL_CONNECTIONS(3)

## CURLMOPT_MAXCONNECTS

See CURLMOPT_MAXCONNECTS(3)

## CURLMOPT_PIPELINING

See CURLMOPT_PIPELINING(3)

## CURLMOPT_PIPELINING_SITE_BL

See CURLMOPT_PIPELINING_SITE_BL(3)

## CURLMOPT_PIPELINING_SERVER_BL

See CURLMOPT_PIPELINING_SERVER_BL(3)

## CURLMOPT_PUSHFUNCTION

See CURLMOPT_PUSHFUNCTION(3)

## CURLMOPT_PUSHDATA

See CURLMOPT_PUSHDATA(3)

## CURLMOPT_SOCKETFUNCTION

See CURLMOPT_SOCKETFUNCTION(3)

## CURLMOPT_SOCKETDATA

See CURLMOPT_SOCKETDATA(3)

## CURLMOPT_TIMERFUNCTION

See CURLMOPT_TIMERFUNCTION(3)

## CURLMOPT_TIMERDATA

See CURLMOPT_TIMERDATA(3)

## CURLMOPT_MAX_CONCURRENT_STREAMS

See CURLMOPT_MAX_CONCURRENT_STREAMS(3)

# EXAMPLE

~~~c

#define MAX_PARALLEL 45

int main(void)
{
  CURLM *multi;
  /* Limit the amount of simultaneous connections curl should allow: */
  curl_multi_setopt(multi, CURLMOPT_MAXCONNECTS, (long)MAX_PARALLEL);
}
~~~

# AVAILABILITY

Added in 7.15.4

# RETURN VALUE

The standard CURLMcode for multi interface error codes. Note that it returns a
CURLM_UNKNOWN_OPTION if you try setting an option that this version of libcurl
does not know of.
