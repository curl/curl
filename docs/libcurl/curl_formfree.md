---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: curl_formfree
Section: 3
Source: libcurl
See-also:
  - curl_formadd (3)
  - curl_mime_free (3)
  - curl_mime_init (3)
---

# NAME

curl_formfree - free a previously build multipart form post chain

# SYNOPSIS

~~~c
#include <curl/curl.h>

void curl_formfree(struct curl_httppost *form);
~~~

# DESCRIPTION

This function is deprecated. Do not use. See curl_mime_init(3) instead!

curl_formfree() is used to clean up data previously built/appended with
curl_formadd(3). This must be called when the data has been used, which
typically means after curl_easy_perform(3) has been called.

The pointer to free is the same pointer you passed to the
CURLOPT_HTTPPOST(3) option, which is the *firstitem* pointer from
the curl_formadd(3) invoke(s).

**form** is the pointer as returned from a previous call to
curl_formadd(3) and may be NULL.

Passing in a NULL pointer in *form* makes this function return immediately
with no action.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    struct curl_httppost *formpost;
    struct curl_httppost *lastptr;

    /* Fill in a file upload field */
    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "file",
                 CURLFORM_FILE, "nice-image.jpg",
                 CURLFORM_END);

    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

    curl_easy_perform(curl);

    /* then cleanup the formpost chain */
    curl_formfree(formpost);
  }
}
~~~

# AVAILABILITY

Deprecated in 7.56.0.

# RETURN VALUE

None
