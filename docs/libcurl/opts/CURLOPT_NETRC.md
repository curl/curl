---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_NETRC
Section: 3
Source: libcurl
See-also:
  - CURLOPT_NETRC_FILE (3)
  - CURLOPT_USERNAME (3)
  - CURLOPT_USERPWD (3)
---

# NAME

CURLOPT_NETRC - enable use of .netrc

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_NETRC, long level);
~~~

# DESCRIPTION

This parameter controls the preference *level* of libcurl between using
user names and passwords from your *~/.netrc* file, relative to user names
and passwords in the URL supplied with CURLOPT_URL(3).

On Windows, libcurl uses the file as *%HOME%/_netrc*. If *%HOME%* is
not set on Windows, libcurl falls back to *%USERPROFILE%*.

You can also tell libcurl a different filename to use with
CURLOPT_NETRC_FILE(3).

libcurl uses a user name (and supplied or prompted password) supplied with
CURLOPT_USERPWD(3) or CURLOPT_USERNAME(3) in preference to any of
the options controlled by this parameter.

Only machine name, user name and password are taken into account (init macros
and similar things are not supported).

libcurl does not verify that the file has the correct properties set (as the
standard Unix ftp client does). It should only be readable by user.

*level* is a long that should be set to one of the values described below.

## CURL_NETRC_IGNORED (0)

libcurl ignores the *.netrc* file. This is the default.

## CURL_NETRC_OPTIONAL (1)

The use of the *.netrc* file is optional, and information in the URL is to
be preferred. The file is scanned for the host and user name (to find the
password only) or for the host only, to find the first user name and password
after that *machine*, which ever information is not specified.

## CURL_NETRC_REQUIRED (2)

The use of the *.netrc* file is required, and any credential information
present in the URL is ignored. The file is scanned for the host and user name
(to find the password only) or for the host only, to find the first user name
and password after that *machine*, which ever information is not
specified.

# FILE FORMAT

The **.netrc** file format is simple: you specify lines with a machine name
and follow the login and password that are associated with that machine.

Each field is provided as a sequence of letters that ends with a space or
newline. Starting in 7.84.0, libcurl also supports quoted strings. They start
and end with double quotes and support the escaped special letters ", n,
r, and t. Quoted strings are the only way a space character can be used in
a user name or password.

## machine <name>

Provides credentials for a host called **name**. libcurl searches the .netrc
file for a machine token that matches the hostname specified in the URL. Once
a match is made, the subsequent tokens are processed, stopping when the end of
file is reached or another "machine" is encountered.

## default

This is the same as "machine" name except that default matches any name. There
can be only one default token, and it must be after all machine tokens. To
provide a default anonymous login for hosts that are not otherwise matched,
add a line similar to this in the end:

 default login anonymous password user@domain

## login <name>

The user name string for the remote machine.

## password <secret>

Supply a password. If this token is present, curl supplies the specified
string if the remote server requires a password as part of the login process.
Note that if this token is present in the .netrc file you really should make
sure the file is not readable by anyone besides the user.

## macdef <name>

Define a macro. This feature is not supported by libcurl. In order for the
rest of the .netrc to still work fine, libcurl properly skips every definition
done with "macdef" that it finds.

# DEFAULT

CURL_NETRC_IGNORED

# PROTOCOLS

Most

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/");
    curl_easy_setopt(curl, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
    ret = curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

Returns CURLE_OK
