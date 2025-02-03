<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: fetch
-->

# String parsing with `strparse`

The functions take input via a pointer to a pointer, which allows the
functions to advance the pointer on success which then by extension allows
"chaining" of functions like this example that gets a word, a space and then a
second word:

~~~c
if(Fetch_str_word(&line, &word1, MAX) ||
   Fetch_str_singlespace(&line) ||
   Fetch_str_word(&line, &word2, MAX))
  fprintf(stderr, "ERROR\n");
~~~

## Strings

The functions that return string information does so by populating a
`struct Fetch_str`:

~~~c
struct Fetch_str {
  char *str;
  size_t len;
};
~~~

## `Fetch_str_word`

~~~c
int Fetch_str_word(char **linep, struct Fetch_str *out, const size_t max);
~~~

Get a sequence of bytes until the first space or the end of the string. Return
non-zero on error. There is no way to include a space in the word, no sort of
escaping. The word must be at least one byte, otherwise it is considered an
error.

`max` is the longest accepted word, or it returns error.

On a successful return, `linep` is updated to point to the byte immediately
following the parsed word.

## `Fetch_str_until`

~~~c
int Fetch_str_until(char **linep, struct Fetch_str *out, const size_t max,
                   char delim);
~~~

Like `Fetch_str_word` but instead of parsing to space, it parses to a given
custom delimiter non-zero byte `delim`.

`max` is the longest accepted word, or it returns error.

The parsed word must be at least one byte, otherwise it is considered an
error.

## `Fetch_str_quotedword`

~~~c
int Fetch_str_quotedword(char **linep, struct Fetch_str *out, const size_t max);
~~~

Get a "quoted" word. This means everything that is provided within a leading
and an ending double character. No escaping possible.

`max` is the longest accepted word, or it returns error.

The parsed word must be at least one byte, otherwise it is considered an
error.

## `Fetch_str_single`

~~~c
int Fetch_str_single(char **linep, char byte);
~~~

Advance over a single character provided in `byte`. Return non-zero on error.

## `Fetch_str_singlespace`

~~~c
int Fetch_str_singlespace(char **linep);
~~~

Advance over a single ASCII space. Return non-zero on error.

## `Fetch_str_number`

~~~c
int Fetch_str_number(char **linep, size_t *nump, size_t max);
~~~

Get an unsigned decimal number. Leading zeroes are just swallowed. Return
non-zero on error.

## `Fetch_str_newline`

~~~c
int Fetch_str_newline(char **linep);
~~~

Check for a single CR or LF. Return non-zero on error */
