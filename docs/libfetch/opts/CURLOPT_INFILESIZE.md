---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_INFILESIZE
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_CONTENT_LENGTH_UPLOAD_T (3)
  - FETCHOPT_INFILESIZE_LARGE (3)
  - FETCHOPT_UPLOAD (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_INFILESIZE - size of the input file to send off

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_INFILESIZE, long filesize);
~~~

# DESCRIPTION

When uploading a file to a remote site, *filesize* should be used to tell
libfetch what the expected size of the input file is. This value must be passed
as a long. See also FETCHOPT_INFILESIZE_LARGE(3) for sending files larger
than 2GB.

For uploading using SCP, this option or FETCHOPT_INFILESIZE_LARGE(3) is
mandatory.

To unset this value again, set it to -1.

Using FETCHOPT_UPLOAD(3) to an HTTP/1.1 server and this value set to -1, makes
libfetch do a chunked transfer-encoded upload.

When sending emails using SMTP, this command can be used to specify the
optional SIZE parameter for the MAIL FROM command.

This option does not limit how much data libfetch actually sends, as that is
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
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    long uploadsize = FILE_SIZE;

    fetch_easy_setopt(fetch, FETCHOPT_URL,
                     "ftp://example.com/destination.tar.gz");

    fetch_easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);

    fetch_easy_setopt(fetch, FETCHOPT_INFILESIZE, uploadsize);

    fetch_easy_perform(fetch);
  }
}
~~~

# HISTORY

SMTP support added in 7.23.0

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
