<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# String parsing with `strparse`

The functions take input via a pointer to a pointer, which allows the
functions to advance the pointer on success which then by extension allows
"chaining" of functions like this example that gets a word, a space and then a
second word:

~~~c
if(Curl_str_word(&line, &word1, MAX) ||
   Curl_str_singlespace(&line) ||
   Curl_str_word(&line, &word2, MAX))
  fprintf(stderr, "ERROR\n");
~~~

## Strings

The functions that return string information does so by populating a
`struct Curl_str`:

~~~c
struct Curl_str {
  char *str;
  size_t len;
};
~~~

Access the struct fields with `Curl_str()` for the pointer and `Curl_strlen()`
for the length rather than using the struct fields directly.

## `Curl_str_init`

~~~c
void Curl_str_init(struct Curl_str *out)
~~~

This initiates a string struct. The parser functions that store info in
strings always init the string themselves, so this stand-alone use is often
not necessary.

## `Curl_str_word`

~~~c
int Curl_str_word(char **linep, struct Curl_str *out, const size_t max);
~~~

Get a sequence of bytes until the first space or the end of the string. Return
non-zero on error. There is no way to include a space in the word, no sort of
escaping. The word must be at least one byte, otherwise it is considered an
error.

`max` is the longest accepted word, or it returns error.

On a successful return, `linep` is updated to point to the byte immediately
following the parsed word.

## `Curl_str_until`

~~~c
int Curl_str_until(char **linep, struct Curl_str *out, const size_t max,
                   char delim);
~~~

Like `Curl_str_word` but instead of parsing to space, it parses to a given
custom delimiter non-zero byte `delim`.

`max` is the longest accepted word, or it returns error.

The parsed word must be at least one byte, otherwise it is considered an
error.

## `Curl_str_quotedword`

~~~c
int Curl_str_quotedword(char **linep, struct Curl_str *out, const size_t max);
~~~

Get a "quoted" word. This means everything that is provided within a leading
and an ending double quote character. No escaping possible.

`max` is the longest accepted word, or it returns error.

The parsed word must be at least one byte, otherwise it is considered an
error.

## `Curl_str_single`

~~~c
int Curl_str_single(char **linep, char byte);
~~~

Advance over a single character provided in `byte`. Return non-zero on error.

## `Curl_str_singlespace`

~~~c
int Curl_str_singlespace(char **linep);
~~~

Advance over a single ASCII space. Return non-zero on error.

## `Curl_str_number`

~~~c
int Curl_str_number(char **linep, curl_size_t *nump, size_t max);
~~~

Get an unsigned decimal number not larger than `max`. Leading zeroes are just
swallowed. Return non-zero on error. Returns error if there was not a single
digit.

## `Curl_str_hex`

~~~c
int Curl_str_hex(char **linep, curl_size_t *nump, size_t max);
~~~

Get an unsigned hexadecimal number not larger than `max`. Leading zeroes are
just swallowed. Return non-zero on error. Returns error if there was not a
single digit. Does *not* handled `0x` prefix.

## `Curl_str_octal`

~~~c
int Curl_str_octal(char **linep, curl_size_t *nump, size_t max);
~~~

Get an unsigned octal number not larger than `max`. Leading zeroes are just
swallowed. Return non-zero on error. Returns error if there was not a single
digit.

## `Curl_str_newline`

~~~c
int Curl_str_newline(char **linep);
~~~

Check for a single CR or LF. Return non-zero on error */

## `Curl_str_casecompare`

~~~c
int Curl_str_casecompare(struct Curl_str *str, const char *check);
~~~

Returns true if the provided string in the `str` argument matches the `check`
string case insensitively.

## `Curl_str_cmp`

~~~c
int Curl_str_cmp(struct Curl_str *str, const char *check);
~~~

Returns true if the provided string in the `str` argument matches the `check`
string case sensitively. This is *not* the same return code as `strcmp`.

## `Curl_str_nudge`

~~~c
int Curl_str_nudge(struct Curl_str *str, size_t num);
~~~

Removes `num` bytes from the beginning (left) of the string kept in `str`. If
`num` is larger than the string, it instead returns an error.
