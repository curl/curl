---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TELNETOPTIONS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPHEADER (3)
  - CURLOPT_QUOTE (3)
---

# NAME

CURLOPT_TELNETOPTIONS - set of telnet options

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TELNETOPTIONS,
                          struct curl_slist *cmds);
~~~

# DESCRIPTION

Provide a pointer to a curl_slist with variables to pass to the telnet
negotiations. The variables should be in the format <option=value>. libcurl
supports the options **TTYPE**, **XDISPLOC** and **NEW_ENV**. See the
TELNET standard for details.

# DEFAULT

NULL

# PROTOCOLS

TELNET

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    struct curl_slist *options;
    options = curl_slist_append(NULL, "TTTYPE=vt100");
    options = curl_slist_append(options, "USER=foobar");
    curl_easy_setopt(curl, CURLOPT_URL, "telnet://example.com/");
    curl_easy_setopt(curl, CURLOPT_TELNETOPTIONS, options);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_slist_free_all(options);
  }
}
~~~

# AVAILABILITY

Along with TELNET

# RETURN VALUE

Returns CURLE_OK if TELNET is supported, and CURLE_UNKNOWN_OPTION if not.
