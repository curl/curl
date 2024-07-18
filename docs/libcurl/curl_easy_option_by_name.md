---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_easy_option_by_name
Section: 3
Source: libcurl
See-also:
  - curl_easy_option_by_id (3)
  - curl_easy_option_next (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.73.0
---

# NAME

curl_easy_option_by_name - find an easy setopt option by name

# SYNOPSIS

~~~c
#include <curl/curl.h>

const struct curl_easyoption *curl_easy_option_by_name(const char *name);
~~~

# DESCRIPTION

Given a **name**, this function returns a pointer to the
*curl_easyoption* struct, holding information about the
curl_easy_setopt(3) option using that name. The name should be specified
without the "CURLOPT_" prefix and the name comparison is made case
insensitive.

If libcurl has no option with the given name, this function returns NULL.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  const struct curl_easyoption *opt = curl_easy_option_by_name("URL");
  if(opt) {
    printf("This option wants CURLoption %x\n", (int)opt->id);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A pointer to the *curl_easyoption* struct for the option or NULL.
