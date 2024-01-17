---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_COOKIE
Section: 3
Source: libcurl
See-also:
  - CURLINFO_COOKIELIST (3)
  - CURLOPT_COOKIEFILE (3)
  - CURLOPT_COOKIEJAR (3)
  - CURLOPT_COOKIELIST (3)
  - CURLOPT_HTTPHEADER (3)
---

# NAME

CURLOPT_COOKIE - HTTP Cookie header

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_COOKIE, char *cookie);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. It is used to set one
or more cookies in the HTTP request. The format of the string should be
NAME=CONTENTS, where NAME is the cookie name and CONTENTS is what the cookie
should contain.

To set multiple cookies, set them all using a single option concatenated like
this: "name1=content1; name2=content2;" etc.

This option sets the cookie header explicitly in the outgoing request(s). If
multiple requests are done due to authentication, followed redirections or
similar, they all get this cookie passed on.

The cookies set by this option are separate from the internal cookie storage
held by the cookie engine and they are not be modified by it. If you enable
the cookie engine and either you have imported a cookie of the same name
(e.g. 'foo') or the server has set one, it has no effect on the cookies you
set here. A request to the server sends both the 'foo' held by the cookie
engine and the 'foo' held by this option. To set a cookie that is instead held
by the cookie engine and can be modified by the server use
CURLOPT_COOKIELIST(3).

Using this option multiple times makes the last set string override the
previous ones.

This option does not enable the cookie engine. Use CURLOPT_COOKIEFILE(3)
or CURLOPT_COOKIEJAR(3) to enable parsing and sending cookies
automatically.

The application does not have to keep the string around after setting this
option.

If libcurl is built with PSL (*Public Suffix List*) support, it detects and
discards cookies that are specified for such suffix domains that should not be
allowed to have cookies. If libcurl is *not* built with PSL support, it has no
ability to stop super cookies. PSL support is identified by the
**CURL_VERSION_PSL** feature bit returned by curl_version_info(3).

# DEFAULT

NULL, no cookies

# PROTOCOLS

HTTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    curl_easy_setopt(curl, CURLOPT_COOKIE, "tool=curl; fun=yes;");

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

If HTTP is enabled

# RETURN VALUE

Returns CURLE_OK if HTTP is enabled, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
