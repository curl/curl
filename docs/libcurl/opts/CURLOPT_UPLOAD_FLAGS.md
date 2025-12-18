---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_UPLOAD_FLAGS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_UPLOAD (3)
Protocol:
  - IMAP
  - IMAPS
Added-in: 8.13.0
---

# NAME

CURLOPT_UPLOAD_FLAGS - upload flags for IMAP

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_UPLOAD_FLAGS, long bitmask);
~~~

# DESCRIPTION

Pass a long as parameter, which is set to a bitmask, to tell libcurl which
flags to send the server relating to uploaded files. The current supported
flags are **CURLULFLAG_ANSWERED**, which sets the **Answered** flag for IMAP
uploads, **CURLULFLAG_DELETED**, which sets the **Deleted** flag for IMAP
uploads, **CURLULFLAG_DRAFT**, which sets the **Draft** flag for IMAP uploads,
**CURLULFLAG_FLAGGED**, which sets the **Flagged** flag for IMAP uploads, and
**CURLULFLAG_SEEN**, which sets the **Seen** flag for IMAP uploads.

# DEFAULT

A bitmask with only the **CURLULFLAG_SEEN** flag set.

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
    curl_off_t fsize = 9876; /* set this to the size of the input file */

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

    /* specify that uploaded mail should be considered flagged */
    curl_easy_setopt(curl, CURLOPT_UPLOAD_FLAGS, CURLULFLAG_FLAGGED);

    /* now specify which pointer to pass to our callback */
    curl_easy_setopt(curl, CURLOPT_READDATA, src);

    /* Set the size of the file to upload */
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)fsize);

    /* perform the upload */
    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
