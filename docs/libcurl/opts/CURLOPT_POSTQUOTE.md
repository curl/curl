---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_POSTQUOTE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PREQUOTE (3)
  - CURLOPT_QUOTE (3)
---

# NAME

CURLOPT_POSTQUOTE - (S)FTP commands to run after the transfer

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_POSTQUOTE,
                          struct curl_slist *cmds);
~~~

# DESCRIPTION

Pass a pointer to a linked list of FTP or SFTP commands to pass to the server
after your FTP transfer request. The commands are only issues if no error
occur. The linked list should be a fully valid list of struct curl_slist
structs properly filled in as described for CURLOPT_QUOTE(3).

Disable this operation again by setting a NULL to this option.

# DEFAULT

NULL

# PROTOCOLS

SFTP and FTP

# EXAMPLE

~~~c
int main(void)
{
  struct curl_slist *cmdlist = NULL;
  cmdlist = curl_slist_append(cmdlist, "RNFR source-name");
  cmdlist = curl_slist_append(cmdlist, "RNTO new-name");

  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/foo.bin");

    /* pass in the FTP commands to run after the transfer */
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, cmdlist);

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

If support for the protocols are built-in.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
