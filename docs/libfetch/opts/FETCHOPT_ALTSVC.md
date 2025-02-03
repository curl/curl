---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_ALTSVC
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_ALTSVC_CTRL (3)
  - FETCHOPT_CONNECT_TO (3)
  - FETCHOPT_COOKIEFILE (3)
  - FETCHOPT_RESOLVE (3)
Protocol:
  - HTTP
Added-in: 7.64.1
---
<!-- markdown-link-check-disable -->
# NAME

FETCHOPT_ALTSVC - alt-svc cache filename

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_ALTSVC, char *filename);
~~~

# DESCRIPTION

Pass in a pointer to a *filename* to instruct libfetch to use that file as
the Alt-Svc cache to read existing cache contents from and possibly also write
it back to after a transfer, unless **FETCHALTSVC_READONLYFILE** is set in
FETCHOPT_ALTSVC_CTRL(3).

Specify a blank filename ("") to make libfetch not load from a file at all.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# SECURITY CONCERNS

libfetch cannot fully protect against attacks where an attacker has write
access to the same directory where it is directed to save files. This is
particularly sensitive if you save files using elevated privileges.

# DEFAULT

NULL. The alt-svc cache is not read nor written to file.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_ALTSVC_CTRL, FETCHALTSVC_H1);
    fetch_easy_setopt(fetch, FETCHOPT_ALTSVC, "altsvc-cache.txt");
    fetch_easy_perform(fetch);
  }
}
~~~

# FILE FORMAT

A text based file with one line per alt-svc entry and each line consists of
nine space-separated fields.

An example line could look like

    h2 www.example.com 8443 h3 second.example.com 443 "20190808 06:18:37" 1 0

The fields of that line are:

## h2

ALPN id for the source origin

## www.example.comp

Hostname for the source origin

## 8443

Port number for the source origin

## h3

ALPN id for the destination host

## second.example.com

Hostname for the destination host

## 443

Port number for the destination host

## 2019*

Expiration date and time of this entry within double quotes. The date format
is "YYYYMMDD HH:MM:SS" and the time zone is GMT.

## 1

Boolean (1 or 0) if "persist" was set for this entry

## 0

Integer priority value (not currently used)

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
