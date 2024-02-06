---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_COPYPOSTFIELDS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_MIMEPOST (3)
  - CURLOPT_POSTFIELDS (3)
  - CURLOPT_POSTFIELDSIZE (3)
  - CURLOPT_UPLOAD (3)
---

# NAME

CURLOPT_COPYPOSTFIELDS - have libcurl copy data to POST

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_COPYPOSTFIELDS, char *data);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should be the full *data* to post in a
HTTP POST operation. It behaves as the CURLOPT_POSTFIELDS(3) option, but the
original data is instead copied by the library, allowing the application to
overwrite the original data after setting this option.

Because data are copied, care must be taken when using this option in
conjunction with CURLOPT_POSTFIELDSIZE(3) or
CURLOPT_POSTFIELDSIZE_LARGE(3): If the size has not been set prior to
CURLOPT_COPYPOSTFIELDS(3), the data is assumed to be a null-terminated
string; else the stored size informs the library about the byte count to
copy. In any case, the size must not be changed after
CURLOPT_COPYPOSTFIELDS(3), unless another CURLOPT_POSTFIELDS(3) or
CURLOPT_COPYPOSTFIELDS(3) option is issued.

# DEFAULT

NULL

# PROTOCOLS

HTTP(S)

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    char local_buffer[1024]="data to send";
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* size of the data to copy from the buffer and send in the request */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 12L);

    /* send data from the local stack */
    curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, local_buffer);

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.17.1

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
