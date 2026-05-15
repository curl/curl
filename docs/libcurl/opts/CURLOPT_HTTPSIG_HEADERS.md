---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HTTPSIG_HEADERS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPSIG (3)
  - CURLOPT_HTTPSIG_KEY (3)
  - CURLOPT_HTTPSIG_KEYID (3)
Protocol:
  - HTTP
Added-in: 8.21.0
---

# NAME

CURLOPT_HTTPSIG_HEADERS - components to sign for HTTP Message Signatures

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HTTPSIG_HEADERS,
                          char *components);
~~~

# DESCRIPTION

Pass a space-separated list of component identifiers to include in the
RFC 9421 HTTP Message Signature.

Derived components start with `@`:

- **\@method** - the HTTP method (GET, POST, etc.)
- **\@authority** - the host and optional port
- **\@path** - the request path
- **\@query** - the query string including the leading `?`

Regular HTTP header names are given without `@`, for example `content-type`
or `content-digest`.

If this option is not set, the default components are **\@method**, **\@authority**,
**\@path** (plus **\@query** when a query string is present).

## Signing request headers

Header components are resolved from the list set with CURLOPT_HTTPHEADER(3)
only. Headers that libcurl adds later (such as the default `User-Agent`) are
**not** visible to the signer unless the application supplies them explicitly.

To sign `User-Agent`, supply it via CURLOPT_HTTPHEADER(3) together with this
option before the transfer; see EXAMPLE.

Each component identifier may appear at most once (RFC 9421 Section 2).
Listing the same component twice returns `CURLE_BAD_FUNCTION_ARGUMENT`.

At most 16 components are accepted; supplying more returns
`CURLE_BAD_FUNCTION_ARGUMENT`.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL (uses the default component set)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  struct curl_slist *headers = NULL;

  if(curl) {
    headers = curl_slist_append(headers, "User-Agent: MyApp/1.0");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/api");
    curl_easy_setopt(curl, CURLOPT_HTTPSIG, (long)CURLHTTPSIG_ED25519);
    curl_easy_setopt(curl, CURLOPT_HTTPSIG_KEY,
                     "9f8362f87a484a954e6e740c5b4c0e84"
                     "229139a20aa8ab56ff66586f6a7d29c5");
    curl_easy_setopt(curl, CURLOPT_HTTPSIG_KEYID, "my-key-id");
    curl_easy_setopt(curl, CURLOPT_HTTPSIG_HEADERS,
                     "@method @authority @path content-type user-agent");
    curl_easy_perform(curl);
    curl_slist_free_all(headers);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
