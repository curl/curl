---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SEEKDATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DEBUGFUNCTION (3)
  - CURLOPT_IOCTLFUNCTION (3)
  - CURLOPT_SEEKFUNCTION (3)
  - CURLOPT_STDERR (3)
Protocol:
  - FTP
  - HTTP
  - SFTP
Added-in: 7.18.0
---

# NAME

CURLOPT_SEEKDATA - pointer passed to the seek callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SEEKDATA, void *pointer);
~~~

# DESCRIPTION

Data *pointer* to pass to the seek callback function. If you use the
CURLOPT_SEEKFUNCTION(3) option, this is the pointer you get as input.

# DEFAULT

If you do not set this, NULL is passed to the callback.

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <unistd.h> /* for lseek() */

struct data {
  int our_fd;
};

static int seek_cb(void *clientp, curl_off_t offset, int origin)
{
  struct data *d = (struct data *)clientp;
  lseek(d->our_fd, offset, origin);
  return CURL_SEEKFUNC_OK;
}

int main(void)
{
  struct data seek_data;
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_SEEKFUNCTION, seek_cb);
    curl_easy_setopt(curl, CURLOPT_SEEKDATA, &seek_data);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE
