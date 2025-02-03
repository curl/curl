---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_NETRC
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_NETRC_FILE (3)
  - FETCHOPT_USERNAME (3)
  - FETCHOPT_USERPWD (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_NETRC - enable use of .netrc

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_NETRC, long level);
~~~

# DESCRIPTION

This parameter controls the preference *level* of libfetch between using
usernames and passwords from your *~/.netrc* file, relative to usernames and
passwords in the URL supplied with FETCHOPT_URL(3).

On Windows, libfetch primarily checks for *.netrc* in *%HOME%*. If *%HOME%* is
not set on Windows, libfetch falls back to *%USERPROFILE%*. If the file does
not exist, it falls back to check if there is instead a file named *_netrc* -
using an underscore instead of period.

You can also tell libfetch a different filename to use with
FETCHOPT_NETRC_FILE(3).

libfetch uses a username (and supplied or prompted password) supplied with
FETCHOPT_USERPWD(3) or FETCHOPT_USERNAME(3) in preference to any of
the options controlled by this parameter.

Only machine name, username and password are taken into account (init macros
and similar things are not supported).

libfetch does not verify that the file has the correct properties set (as the
standard Unix ftp client does). It should only be readable by user.

*level* is a long that should be set to one of the values described below.

## FETCH_NETRC_IGNORED (0)

libfetch ignores the *.netrc* file. This is the default.

## FETCH_NETRC_OPTIONAL (1)

The use of the *.netrc* file is optional, and information in the URL is to
be preferred. The file is scanned for the host and username (to find the
password only) or for the host only, to find the first username and password
after that *machine*, which ever information is not specified.

## FETCH_NETRC_REQUIRED (2)

The use of the *.netrc* file is required, and any credential information
present in the URL is ignored. The file is scanned for the host and username
(to find the password only) or for the host only, to find the first username
and password after that *machine*, which ever information is not
specified.

# FILE FORMAT

The **.netrc** file format is simple: you specify lines with a machine name
and follow the login and password that are associated with that machine.

Each field is provided as a sequence of letters that ends with a space or
newline. Starting in 7.84.0, libfetch also supports quoted strings. They start
and end with double quotes and support the escaped special letters ", n,
r, and t. Quoted strings are the only way a space character can be used in
a username or password.

## machine \<name\>

Provides credentials for a host called **name**. libfetch searches the .netrc
file for a machine token that matches the hostname specified in the URL. Once
a match is made, the subsequent tokens are processed, stopping when the end of
file is reached or another "machine" is encountered.

## default

This is the same as machine name except that default matches any name. There
can be only one default token, and it must be after all machine tokens. To
provide a default anonymous login for hosts that are not otherwise matched,
add a line similar to this in the end:

    default login anonymous password user@domain

## login \<name\>

The username string for the remote machine.

## password \<secret\>

Supply a password. If this token is present, fetch supplies the specified
string if the remote server requires a password as part of the login process.
Note that if this token is present in the .netrc file you really should make
sure the file is not readable by anyone besides the user.

## macdef \<name\>

Define a macro. This feature is not supported by libfetch. In order for the
rest of the .netrc to still work fine, libfetch properly skips every definition
done with "macdef" that it finds.

# DEFAULT

FETCH_NETRC_IGNORED

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_NETRC, FETCH_NETRC_OPTIONAL);
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
