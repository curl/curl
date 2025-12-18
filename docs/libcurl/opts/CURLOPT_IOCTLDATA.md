---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_IOCTLDATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_IOCTLFUNCTION (3)
  - CURLOPT_SEEKFUNCTION (3)
Protocol:
  - All
Added-in: 7.12.3
---

# NAME

CURLOPT_IOCTLDATA - pointer passed to I/O callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_IOCTLDATA, void *pointer);
~~~

# DESCRIPTION

Pass the *pointer* that is untouched by libcurl and passed as the 3rd
argument in the ioctl callback set with CURLOPT_IOCTLFUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <unistd.h> /* for lseek */

struct data {
  int fd; /* our file descriptor */
};

static curlioerr ioctl_callback(CURL *handle, int cmd, void *clientp)
{
  struct data *io = (struct data *)clientp;
  if(cmd == CURLIOCMD_RESTARTREAD) {
    lseek(io->fd, 0, SEEK_SET);
    return CURLIOE_OK;
  }
  return CURLIOE_UNKNOWNCMD;
}
int main(void)
{
  struct data ioctl_data;
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_IOCTLFUNCTION, ioctl_callback);
    curl_easy_setopt(curl, CURLOPT_IOCTLDATA, &ioctl_data);
  }
}
~~~

# DEPRECATED

Deprecated since 7.18.0.

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
