---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PREQUOTE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_POSTQUOTE (3)
  - CURLOPT_QUOTE (3)
Protocol:
  - FTP
---

# NAME

CURLOPT_PREQUOTE - commands to run before an FTP transfer

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PREQUOTE,
                          struct curl_slist *cmds);
~~~

# DESCRIPTION

Pass a pointer to a linked list of FTP commands to pass to the server after
the transfer type is set. The linked list should be a fully valid list of
struct curl_slist structs properly filled in as described for
CURLOPT_QUOTE(3). Disable this operation again by setting a NULL to this
option.

These commands are not performed when a directory listing is performed, only
for file transfers.

While CURLOPT_QUOTE(3) and CURLOPT_POSTQUOTE(3) work for SFTP,
this option does not.

# DEFAULT

NULL

# EXAMPLE

~~~c
int main(void)
{
  struct curl_slist *cmdlist = NULL;
  cmdlist = curl_slist_append(cmdlist, "SYST");

  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/foo.bin");

    /* pass in the FTP commands to run */
    curl_easy_setopt(curl, CURLOPT_PREQUOTE, cmdlist);

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Along with the protocol support

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
