---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_FTP_FILEMETHOD
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DIRLISTONLY (3)
  - CURLOPT_FTP_SKIP_PASV_IP (3)
---

# NAME

CURLOPT_FTP_FILEMETHOD - select directory traversing method for FTP

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FTP_FILEMETHOD,
                          long method);
~~~

# DESCRIPTION

Pass a long telling libcurl which *method* to use to reach a file on a
FTP(S) server.

This option exists because some server implementations are not compliant to
what the standards say should work.

The argument should be one of the following alternatives:

## CURLFTPMETHOD_MULTICWD

libcurl does a single CWD operation for each path part in the given URL. For
deep hierarchies this means many commands. This is how RFC 1738 says it should
be done. This is the default but the slowest behavior.

## CURLFTPMETHOD_NOCWD

libcurl makes no CWD at all. libcurl does SIZE, RETR, STOR etc and gives a
full path to the server for all these commands. This is the fastest behavior
since it skips having to change directories.

## CURLFTPMETHOD_SINGLECWD

libcurl does one CWD with the full target directory and then operates on the
file &"normally" (like in the multicwd case). This is somewhat more standards
compliant than 'nocwd' but without the full penalty of 'multicwd'.

# DEFAULT

CURLFTPMETHOD_MULTICWD

# PROTOCOLS

FTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/1/2/3/4/new.txt");
    curl_easy_setopt(curl, CURLOPT_FTP_FILEMETHOD,
                     (long)CURLFTPMETHOD_SINGLECWD);

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.15.1

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
