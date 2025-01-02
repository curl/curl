---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_MAIL_RCPT_ALLOWFAILS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_MAIL_FROM (3)
  - CURLOPT_MAIL_RCPT (3)
Protocol:
  - SMTP
Added-in: 8.2.0
---

# NAME

CURLOPT_MAIL_RCPT_ALLOWFAILS - allow RCPT TO command to fail for some recipients

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_MAIL_RCPT_ALLOWFAILS,
                          long allow);
~~~

# DESCRIPTION

If *allow* is set to 1L, allow RCPT TO command to fail for some recipients.

When sending data to multiple recipients, by default curl aborts the SMTP
conversation if either one of the recipients causes the RCPT TO command to
return an error.

The default behavior can be changed by setting *allow* to 1L which makes
libcurl ignore errors for individual recipients and proceed with the remaining
accepted recipients.

If all recipients trigger RCPT TO failures and this flag is specified, curl
aborts the SMTP conversation and returns the error received from to the last
RCPT TO command.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    struct curl_slist *list;
    CURLcode res;

    /* Adding one valid and one invalid email address */
    list = curl_slist_append(NULL, "person@example.com");
    list = curl_slist_append(list, "invalidemailaddress");

    curl_easy_setopt(curl, CURLOPT_URL, "smtp://example.com/");
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT_ALLOWFAILS, 1L);

    res = curl_easy_perform(curl);
    curl_slist_free_all(list);
    curl_easy_cleanup(curl);
  }
}
~~~

# HISTORY

This option was called CURLOPT_MAIL_RCPT_ALLLOWFAILS (with three instead of
two letter L) before 8.2.0

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
