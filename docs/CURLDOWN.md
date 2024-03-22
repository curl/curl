# curldown

A markdown-like syntax for libcurl man pages.

## Purpose

A text format for writing libcurl documentation in the shape of man pages.

Make it easier for users to contribute and write documentation. A format that
is easier on the eye in its source format.

Make it harder to do syntactical mistakes.

Use a format that allows creating man pages that end up looking exactly like
the man pages did when we wrote them in nroff format.

Take advantage of the fact that people these days are accustomed to markdown
by using a markdown-like syntax.

This allows us to fix issues in the nroff format easier since now we generate
them. For example: escaping minus to prevent them from being turned into
Unicode by man.

Generate nroff output that looks (next to) *identical* to the previous files,
so that the look, existing test cases, HTML conversions, existing
infrastructure etc remain mostly intact.

Contains meta-data in a structured way to allow better output (for example the
see also information) and general awareness of what the file is about.

## File extension

Since curldown looks similar to markdown, we use `.md` extensions on the
files.

## Conversion

Convert **from curldown to nroff** with `cd2nroff`. Generates nroff man pages.

Convert **from nroff to curldown** with `nroff2cd`. This is only meant to be
used for the initial conversion to curldown and should ideally never be needed
again.

Convert, check or clean up an existing curldown to nicer, better, cleaner
curldown with **cd2cd**.

Mass-convert all curldown files to nroff in specified directories with
`cdall`:

    cdall [dir1] [dir2] [dir3] ..

## Known issues

The `cd2nroff` tool does not yet handle *italics* or **bold** where the start
and the end markers are used on separate lines.

The `nroff2cd` tool generates code style quotes for all `.fi` sections since
the nroff format does not carry a distinction.

# Format

Each curldown starts with a header with meta-data:

    ---
    c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
    SPDX-License-Identifier: curl
    Title: CURLOPT_AWS_SIGV4
    Section: 3
    Source: libcurl
    Protocol:
      - HTTP
    See-also:
      - CURLOPT_HEADEROPT (3)
      - CURLOPT_HTTPAUTH (3)
    TLS-backend:
      - [name]
    ---

All curldown files *must* have all the headers present and at least one
`See-also:` entry specified.

If the man page is for section 3 (library related). The `Protocol` list must
contain at least one protocol, which can be `*` if the option is virtually for
everything. If `*` is used, it must be the only listed protocol. Recognized
protocols are either URL schemes (in uppercase), `TLS` or `TCP`.

If the `Protocol` list contains `TLS`, then there must also be a `TLS-backend`
list, specifying `All` or a list of what TLS backends that work with this
option. The available TLS backends are:

- `BearSSL`
- `GnuTLS`
- `mbedTLS`
- `OpenSSL` (also covers BoringSSL, libressl, quictls, AWS-LC and AmiSSL)
- `rustls`
- `Schannel`
- `Secure Transport`
- `wolfSSL`
- `All`: all TLS backends

Following the header in the file, is the manual page using markdown-like
syntax:

~~~
    # NAME
    a page - this is a page descriving something

    # SYNOPSIS
    ~~~c
    #include <curl/curl.h>

    CURLcode curl_easy_setopt(CURL *handle, CURLOPT_AWS_SIGV4, char *param);
    ~~~
~~~

Quoted source code should start with `~~~c` and end with `~~~` while regular
quotes can start with `~~~` or just be indented with 4 spaces.

Headers at top-level `#` get converted to `.SH`.

`nroff2cd` supports the `##` next level header which gets converted to `.IP`.

Write bold words or phrases within `**` like:

    This is a **bold** word.

Write italics like:

    This is *italics*.

Due to how man pages do not support backticks especially formatted, such
occurrences in the source are instead just using italics in the generated
output:

    This `word` appears in italics.

When generating the nroff output, the tooling removes superfluous newlines,
meaning they can be used freely in the source file to make the text more
readable.

To make sure curldown documents render correctly as markdown, all literal
occurrences of `<` or `>` need to be escaped by a leading backslash.

## symbols

All mentioned curl symbols that have their own man pages, like
`curl_easy_perform(3)` are automatically rendered using italics in the output
without having to enclose it with asterisks. This helps ensuring that they get
converted to links properly later in the HTML version on the website, as
converted with `roffit`. This makes the curldown text easier to read even when
mentioning many curl symbols.

This auto-linking works for patterns matching `(lib|)curl[^ ]*(3)`.
