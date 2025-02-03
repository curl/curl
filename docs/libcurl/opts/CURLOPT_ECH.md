---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_ECH
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DOH_URL (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - wolfSSL
Added-in: 8.8.0
---

# NAME

FETCHOPT_ECH - configuration for Encrypted Client Hello

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_ECH, char *config);
~~~

# DESCRIPTION

ECH is only compatible with TLSv1.3.

This experimental feature requires a special build of OpenSSL, as ECH is not
yet supported in OpenSSL releases. In contrast ECH is supported by the latest
BoringSSL and wolfSSL releases.

There is also a known issue with using wolfSSL which does not support ECH when
the HelloRetryRequest mechanism is used.

Pass a string that specifies configuration details for ECH. In all cases, if
ECH is attempted, it may fail for various reasons. The keywords supported are:

## false

Turns off ECH.

## grease

Instructs client to emit a GREASE ECH extension. (The connection fails if ECH
is attempted but fails.)

## true

Instructs client to attempt ECH, if possible, but to not fail if attempting
ECH is not possible.

## hard

Instructs client to attempt ECH and fail if attempting ECH is not possible.

## ecl:\<base64-value\>

If the string starts with `ecl:` then the remainder of the string should be a
base64-encoded ECHConfigList that is used for ECH rather than attempting to
download such a value from the DNS.

## pn:\<name\>

If the string starts with `pn:` then the remainder of the string should be a
DNS/hostname that is used to over-ride the public_name field of the
ECHConfigList that is used for ECH.

##

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL or "false" to disable its use again.

# DEFAULT

NULL, meaning ECH is disabled.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();

  const char *config = \
    "ecl:AED+DQA87wAgACB/RuzUCsW3uBbSFI7mzD63TUXpI8sGDTnFTbFCDpa+" \
    "CAAEAAEAAQANY292ZXIuZGVmby5pZQAA";
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_ECH, config);
    fetch_easy_perform(fetch);
  }
}
~~~
# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
