---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_DIRLISTONLY
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CUSTOMREQUEST (3)
  - CURLOPT_WILDCARDMATCH (3)
Protocol:
  - FTP
  - SFTP
  - POP3
---

# NAME

CURLOPT_DIRLISTONLY - ask for names only in a directory listing

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_DIRLISTONLY, long listonly);
~~~

# DESCRIPTION

For FTP and SFTP based URLs a parameter set to 1 tells the library to list the
names of files in a directory, rather than performing a full directory listing
that would normally include file sizes, dates etc.

For POP3 a parameter of 1 tells the library to list the email message or
messages on the POP3 server. This can be used to change the default behavior
of libcurl, when combined with a URL that contains a message ID, to perform a
"scan listing" which can then be used to determine the size of an email.

Note: For FTP this causes a NLST command to be sent to the FTP server. Beware
that some FTP servers list only files in their response to NLST; they might
not include subdirectories and symbolic links.

Setting this option to 1 also implies a directory listing even if the URL
does not end with a slash, which otherwise is necessary.

Do not use this option if you also use CURLOPT_WILDCARDMATCH(3) as it
effectively breaks that feature.

# DEFAULT

0, disabled

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/dir/");

    /* list only */
    curl_easy_setopt(curl, CURLOPT_DIRLISTONLY, 1L);

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

This option was known as CURLOPT_FTPLISTONLY up to 7.16.4. POP3 is supported
since 7.21.5.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
