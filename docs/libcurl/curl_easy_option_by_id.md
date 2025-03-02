---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_easy_option_by_id
Section: 3
Source: libcurl
See-also:
  - curl_easy_option_by_name (3)
  - curl_easy_option_next (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.73.0
---

# NAME

curl_easy_option_by_id - find an easy setopt option by id

# SYNOPSIS

~~~c
#include <curl/curl.h>

const struct curl_easyoption *curl_easy_option_by_id(CURLoption id);
~~~

# DESCRIPTION

Given a *CURLoption* **id**, this function returns a pointer to the
*curl_easyoption* struct, holding information about the curl_easy_setopt(3)
option using that id. The option id is the `CURLOPT_` prefixed ones provided
in the standard curl/curl.h header file. This function returns the non-alias
version of the cases where there is an alias function as well.

If libcurl has no option with the given id, this function returns NULL.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  const struct curl_easyoption *opt = curl_easy_option_by_id(CURLOPT_URL);
  if(opt) {
    printf("This option wants type %x\n", opt->type);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A pointer to the *curl_easyoption* struct for the option or NULL.
