---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_ECH
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DOH_URL (3)
---

# NAME

CURLOPT_ECH - configuration for Encrypted Client Hello

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_ECH, char *config);
~~~

# DESCRIPTION

Pass a string that specifies configuration details for ECH.
In all cases, if ECH is attempted, it may fail for various reasons.
The keywords supported are:

## false
Turns off ECH.
## grease
Instructs client to emit a GREASE ECH extension.
(The connection will fail if ECH is attempted but fails.)
## true
Instructs client to attempt ECH, if possible, but to not fail if attempting ECH is not possible.
## hard
Instructs client to attempt ECH and fail if if attempting ECH is not possible.
## ecl:<base64-value>
If the string starts with "ecl:" then the remainder of the string should be a base64-encoded
ECHConfigList that is used for ECH rather than attempting to download such a value from
the DNS.
## pn:<name>
If the string starts with "pn:" then the remainder of the string should be a DNS/hostname
that is used to over-ride the public_name field of the ECHConfigList that will be used
for ECH.

# DEFAULT

NULL, meaning ECH is disabled.

# PROTOCOLS

TLS, and requires TLS1.3.

# EXAMPLE

~~~c
CURL *curl = curl_easy_init();

const char *config ="ecl:AED+DQA87wAgACB/RuzUCsW3uBbSFI7mzD63TUXpI8sGDTnFTbFCDpa+CAAEAAEAAQANY292ZXIuZGVmby5pZQAA";
if(curl) {
  curl_easy_setopt(curl, CURLOPT_ECH, config);
  curl_easy_perform(curl);
}
~~~


# AVAILABILITY

Added in 8.6.0

# RETURN VALUE

Returns CURLE_OK on success or CURLE_OUT_OF_MEMORY if there was insufficient heap space.
