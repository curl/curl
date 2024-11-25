---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_IMAP_UPLOAD_UNREAD
Section: 3
Source: libcurl
See-also:
Protocol:
  - IMAP
  - IMAPS
Added-in: 8.12.0
---

# NAME

CURLOPT_IMAP_UPLOAD_UNREAD - specify that uploaded mail has not been read

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_IMAP_UPLOAD_UNREAD, long uploadunread);
~~~

# DESCRIPTION

For IMAP and IMAPS, setting this parameter to 1 when uploading mail tells the
server that the mail has not yet been seen. This overrides curl's default
behavior, which is to tell the server that uploaded mail has already been seen.

# DEFAULT

0, disabled

# %PROTOCOLS%

# EXAMPLE

~~~c
static size_t read_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  FILE *src = userdata;
  /* copy as much data as possible into the 'ptr' buffer, but no more than
     'size' * 'nmemb' bytes */
  size_t retcode = fread(ptr, size, nmemb, src);

  return retcode;
}

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    FILE *src = fopen("local-file", "r");
    curl_off_t fsize; /* set this to the size of the input file */

    /* we want to use our own read function */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_cb);

    /* enable uploading */
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    /* specify target */
    curl_easy_setopt(curl, CURLOPT_URL, "imap://example.com:993/mailbox");

    /* provide username */
    curl_easy_setopt(curl, CURLOPT_USERNAME, "user@example.com");

    /* provide password */
    curl_easy_setopt(curl, CURLOPT_PASSWORD, "password");

    /* specify that uploaded mail should be considered unread */
    curl_easy_setopt(curl, CURLOPT_IMAP_UPLOAD_UNREAD, 1L);

    /* now specify which pointer to pass to our callback */
    curl_easy_setopt(curl, CURLOPT_READDATA, src);

    /* Set the size of the file to upload */
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)fsize);

    /* perform the upload */
    curl_easy_perform(curl);
  }
}
~~~

# HISTORY

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
