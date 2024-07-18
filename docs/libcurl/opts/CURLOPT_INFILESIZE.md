---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_INFILESIZE
Section: 3
Source: libcurl
See-also:
  - CURLINFO_CONTENT_LENGTH_UPLOAD_T (3)
  - CURLOPT_INFILESIZE_LARGE (3)
  - CURLOPT_UPLOAD (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

CURLOPT_INFILESIZE - size of the input file to send off

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_INFILESIZE, long filesize);
~~~

# DESCRIPTION

When uploading a file to a remote site, *filesize* should be used to tell
libcurl what the expected size of the input file is. This value must be passed
as a long. See also CURLOPT_INFILESIZE_LARGE(3) for sending files larger
than 2GB.

For uploading using SCP, this option or CURLOPT_INFILESIZE_LARGE(3) is
mandatory.

To unset this value again, set it to -1.

Using CURLOPT_UPLOAD(3) to an HTTP/1.1 server and this value set to -1, makes
libcurl do a chunked transfer-encoded upload.

When sending emails using SMTP, this command can be used to specify the
optional SIZE parameter for the MAIL FROM command.

This option does not limit how much data libcurl actually sends, as that is
controlled entirely by what the read callback returns, but telling one value
and sending a different amount may lead to errors.

# DEFAULT

Unset

# %PROTOCOLS%

# EXAMPLE

~~~c

#define FILE_SIZE 12345L

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    long uploadsize = FILE_SIZE;

    curl_easy_setopt(curl, CURLOPT_URL,
                     "ftp://example.com/destination.tar.gz");

    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    curl_easy_setopt(curl, CURLOPT_INFILESIZE, uploadsize);

    curl_easy_perform(curl);
  }
}
~~~

# HISTORY

SMTP support added in 7.23.0

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
