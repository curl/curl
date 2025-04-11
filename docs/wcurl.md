---
c: Copyright (C) Samuel Henrique <samueloph@debian.org>, Sergio Durigan Junior <sergiodj@debian.org> and many contributors, see the AUTHORS file.
SPDX-License-Identifier: curl
Title: wcurl
Section: 1
Source: wcurl
See-also:
  - curl (1)
  - trurl (1)
Added-in: n/a
---

# NAME

**wcurl** - a simple wrapper around curl to easily download files.

# SYNOPSIS

**wcurl \<URL\>...**

**wcurl [--curl-options \<CURL_OPTIONS\>]... [--dry-run] [--no-decode-filename] [-o|-O|--output \<PATH\>] [--] \<URL\>...**

**wcurl [--curl-options=\<CURL_OPTIONS\>]... [--dry-run] [--no-decode-filename] [--output=\<PATH\>] [--] \<URL\>...**

**wcurl -V|--version**

**wcurl -h|--help**

# DESCRIPTION

**wcurl** is a simple curl wrapper which lets you use curl to download files
without having to remember any parameters.

Simply call **wcurl** with a list of URLs you want to download and **wcurl**
picks sane defaults.

If you need anything more complex, you can provide any of curl's supported
parameters via the **--curl-options** option. Just beware that you likely
should be using curl directly if your use case is not covered.

By default, **wcurl** does:

## * Percent-encode whitespaces in URLs;

## * Download multiple URLs in parallel
    if the installed curl's version is \>= 7.66.0 (--parallel);

## * Follow redirects;

## * Automatically choose a filename as output;

## * Avoid overwriting files
     if the installed curl's version is \>= 7.83.0 (--no-clobber);

## * Perform retries;

## * Set the downloaded file timestamp
    to the value provided by the server, if available;

## * Default to https
    if the URL does not contain any scheme;

## * Disable curl's URL globbing parser
    so {} and [] characters in URLs are not treated specially;

## * Percent-decode the resulting filename;

## * Use 'index.html' as the default filename
    if there is none in the URL.

# OPTIONS

## --curl-options, --curl-options=\<CURL_OPTIONS\>...

Specify extra options to be passed when invoking curl. May be specified more
than once.

## -o, -O, --output, --output=\<PATH\>

Use the provided output path instead of getting it from the URL. If multiple
URLs are provided, resulting files share the same name with a number appended to
the end (curl \>= 7.83.0). If this option is provided multiple times, only the
last value is considered.

## --no-decode-filename

Don't percent-decode the output filename, even if the percent-encoding in the
URL was done by **wcurl**, e.g.: The URL contained whitespaces.

## --dry-run

Do not actually execute curl, just print what would be invoked.

## -V, \--version

Print version information.

## -h, \--help

Print help message.

# CURL_OPTIONS

Any option supported by curl can be set here. This is not used by **wcurl**; it
is instead forwarded to the curl invocation.

# URL

URL to be downloaded. Anything that is not a parameter is considered
an URL. Whitespaces are percent-encoded and the URL is passed to curl, which
then performs the parsing. May be specified more than once.

# EXAMPLES

Download a single file:

**wcurl example.com/filename.txt**

Download two files in parallel:

**wcurl example.com/filename1.txt example.com/filename2.txt**

Download a file passing the **--progress-bar** and **--http2** flags to curl:

**wcurl --curl-options="--progress-bar --http2" example.com/filename.txt**

Resume from an interrupted download (if more options are used, this needs to
be the last one in the list):

**wcurl --curl-options="--continue-at -" example.com/filename.txt**

# AUTHORS

    Samuel Henrique \<samueloph@debian.org\>
    Sergio Durigan Junior \<sergiodj@debian.org\>
    and many contributors, see the AUTHORS file.

# REPORTING BUGS

If you experience any problems with **wcurl** that you do not experience with
curl, submit an issue on Github: https://github.com/curl/wcurl

# COPYRIGHT

**wcurl** is licensed under the curl license
