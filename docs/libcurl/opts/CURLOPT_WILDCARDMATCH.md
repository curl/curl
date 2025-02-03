---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_WILDCARDMATCH
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CHUNK_BGN_FUNCTION (3)
  - FETCHOPT_CHUNK_END_FUNCTION (3)
  - FETCHOPT_FNMATCH_FUNCTION (3)
  - FETCHOPT_URL (3)
Protocol:
  - FTP
Added-in: 7.21.0
---

# NAME

FETCHOPT_WILDCARDMATCH - directory wildcard transfers

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_WILDCARDMATCH, long onoff);
~~~

# DESCRIPTION

Set *onoff* to 1 if you want to transfer multiple files according to a
filename pattern. The pattern can be specified as part of the FETCHOPT_URL(3)
option, using an **fnmatch**-like pattern (Shell Pattern Matching) in the last
part of URL (filename).

By default, libfetch uses its internal wildcard matching implementation. You
can provide your own matching function by the
FETCHOPT_FNMATCH_FUNCTION(3) option.

A brief introduction of its syntax follows:

## * - ASTERISK

    ftp://example.com/some/path/*.txt

matches all `.txt` files in the root directory. Only two asterisks are allowed
within the same pattern string.

## ? - QUESTION MARK

Question mark matches any (exactly one) character.

    ftp://example.com/some/path/photo?.jpg

## [ - BRACKET EXPRESSION

The left bracket opens a bracket expression. The question mark and asterisk have
no special meaning in a bracket expression. Each bracket expression ends by the
right bracket and matches exactly one character. Some examples follow:

**[a-zA-Z0-9]** or **[f-gF-G]** - character interval

**[abc]** - character enumeration

**[^abc]** or **[!abc]** - negation

**[[:name:]]** class expression. Supported classes are **alnum**,**lower**,
**space**, **alpha**, **digit**, **print**, **upper**, **blank**, **graph**,
**xdigit**.

**[][-!^]** - special case - matches only '-', ']', '[', '!' or '^'. These
characters have no special purpose.

**[[]]** - escape syntax. Matches '[', ']' or 'e'.

Using the rules above, a filename pattern can be constructed:

    ftp://example.com/some/path/[a-z[:upper:]\\].jpg

# %PROTOCOLS%

# EXAMPLE

~~~c
extern long begin_cb(struct fetch_fileinfo *, void *, int);
extern long end_cb(void *ptr);

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    /* turn on wildcard matching */
    fetch_easy_setopt(fetch, FETCHOPT_WILDCARDMATCH, 1L);

    /* callback is called before download of concrete file started */
    fetch_easy_setopt(fetch, FETCHOPT_CHUNK_BGN_FUNCTION, begin_cb);

    /* callback is called after data from the file have been transferred */
    fetch_easy_setopt(fetch, FETCHOPT_CHUNK_END_FUNCTION, end_cb);

    /* See more on https://fetch.se/libfetch/c/ftp-wildcard.html */
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
