# curldown

A markdown-like syntax for writing libcurl man pages.

## Purpose

Provide a more easily used text format for writing libcurl documentation in
the shape of man pages.

Make it easier for users to contribute and write documentation.

Make it harder to do syntactical mistakes in man pages.

Use a format that allows creating man pages that end up looking exactly like
the man pages did when we authored them in nroff format.

Take advantage of the fact that people these days are accustomed to markdown
by using a markdown-like syntax.

To allow us to fix minor issues in the nroff format easier since how we
generate them with a tool. For example: escaping minus to prevent them from
being turned into unicode by man.

## File extension

Since it is curldown, not markdown, we use `.cd` extensions on such files.

## Conversion

Convert from curldown to nroff with `cd2nroff`. This script is meant to get
run when generating man pages to ship in tarballs etc.

Convert from nroff to curldown with `nroff2cd`. This is only meant to be used
for the initial conversion to curldown and should ideally never be needed
again.

Mass-convert all `.cd` to `.3` in specified directories:

    cdall.pl [dir1] [dir2] [dir3] ..

## Known issues

The `cd2nroff` tool does not yet handle *italics* or **bold** where the start
and the end markers are used on separate lines.

The `nroff2cd` tool generates code style quotes for all `.fi` sections since
the nroff format does not carry a distinction.

# Format

Each curldown starts with a header with meta-data:

    ---
    c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
    SPDX-License-Identifier: curl
    Title: CURLOPT_AWS_SIGV4
    Section: 3
    Source: libcurl
    See-also: CURLOPT_HEADEROPT (3)
    See-also: CURLOPT_HTTPAUTH (3)
    ---

Following the header, is the manual page.

    # NAME
    a page - this is a page descriving something

    # SYNOPSIS
    ~~~c
    #include <curl/curl.h>

    CURLcode curl_easy_setopt(CURL *handle, CURLOPT_AWS_SIGV4, char *param);
    ~~~

It also supports the `##` next level header.

Write bold words phrases within `**` like:

    This is a **bold** word.

Write italics `*` like:

    This is *italics*.

Due to how man pages don't support backticks especially formatted, such
occurances in the source will instead just use italics in the generated
output:

    This `word` appears in italics.
