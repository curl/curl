---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_FTP_CREATE_MISSING_DIRS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FTP_FILEMETHOD (3)
  - CURLOPT_FTP_USE_EPSV (3)
---

# NAME

CURLOPT_FTP_CREATE_MISSING_DIRS - create missing directories for FTP and SFTP

# SYNOPSIS

~~~c
#include <curl/curl.h>

typedef enum {
  CURLFTP_CREATE_DIR_NONE,
  CURLFTP_CREATE_DIR,
  CURLFTP_CREATE_DIR_RETRY
} curl_ftpcreatedir;

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FTP_CREATE_MISSING_DIRS,
                          long create);
~~~

# DESCRIPTION

Pass a long telling libcurl to *create* the dir. If the value is
*CURLFTP_CREATE_DIR* (1), libcurl may create any remote directory that it
fails to "move" into.

For FTP requests, that means a CWD command fails. CWD being the command that
changes working directory.

For SFTP requests, libcurl may create the remote directory if it cannot obtain
a handle to the target-location. The creation fails if a file of the same name
as the directory to create already exists or lack of permissions prevents
creation.

Setting *create* to *CURLFTP_CREATE_DIR_RETRY* (2), tells libcurl to
retry the CWD command again if the subsequent **MKD** command fails. This is
especially useful if you are doing many simultaneous connections against the
same server and they all have this option enabled, as then CWD may first fail
but then another connection does **MKD** before this connection and thus
**MKD** fails but trying CWD works!

# DEFAULT

CURLFTP_CREATE_DIR_NONE (0)

# PROTOCOLS

FTP and SFTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL,
                     "ftp://example.com/non-existing/new.txt");
    curl_easy_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS,
                     (long)CURLFTP_CREATE_DIR_RETRY);

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.10.7. SFTP support added in 7.16.3. The retry option was added in
7.19.4.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if the
create value is not.
