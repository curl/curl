<!--
  Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

  SPDX-License-Identifier: curl
-->

# curl man page generator

`managen` is the curl man page generator. It generates a single nroff man page
output from the set of sources files in this directory.

The `mainpage.idx` file lists all files that are rendered in that order to
produce the output. The magic `%options` keyword inserts all command line
options documented.

The `%options` documentation is created with one source file for each
supported command line option.

The documentation file format is described below. It is meant to look similar
to markdown which is why it uses `.md` file extensions.

## Option files

Each command line option is described in a file named `<long name>.d`, where
option name is written without any prefixing dashes. Like the filename for the
`-v, --verbose` option is named `verbose.d`.

Each file has a set of meta-data in the top of the file, followed by a body of
text.

The documentation files that do not document options have no meta-data part.

A line that starts with `<!--` is a comment. It should also end with `-->`.

### Meta-data

    --- (start of meta-data)
    Added: (version number in which this was added)
    Arg: (the argument the option takes)
    c: (copyright line)
    Example:
      - (an example command line, without "curl" and can use `$URL`)
      - (another example)
    Experimental: yes (if so)
    Help: (short text for the --help output for this option)
    Long: (long form name, without dashes)
    Magic: (description of "magic" options)
    Multi: single/append/boolean/mutex/custom/per-URL (if used more than once)
    Mutexed: (space separated list of options this overrides, no dashes)
    Protocols: (space separated list for which protocols this option works)
    Requires: (space separated list of features this requires, no dashes)
    Scope: global (if the option is global)
    See-also:
      - (a related option, no dashes)
      - (another related option, no dashes)
    Short: (single letter, without dash)
    SPDX-License-Identifier: curl
    Tags: (space separated list)
    --- (end of meta-data)

### Body

The body of the description. Only refer to options with their long form option
version, like `--verbose`. The output generator replaces such option with the
correct markup that shows both short and long version.

Text written within `*asterisks*` is shown using italics. Text within two
`**asterisks**` is shown using bold.

Text that is prefixed with a space is treated like an "example" and gets
output in monospace.

Within the body, describe a list of items like this:

    ## item 1
    description

    ## item 2
    second description

The list is automatically terminated at end of file, or you can do it
explicitly with an empty "header":

    ##

Angle brackets (`<>`) need to be escaped when used in text like `\<` and
`\>`. This, to ensure that the text renders nicely as markdown.

### Headers

The `#` header can be used by non-option files and it produces a
`.SH` output.

If the `#` header is used for a command line option file, that header is
simply ignored in the generated output. It can still serve a purpose in the
source file as it helps the user identify what option the file is for.

### Variables

There are three different "variables" that can be used when creating the
output. They need to be written within backticks in the source file (to escape
getting spellchecked by CI jobs): `%DATE`, `%VERSION` and `%GLOBALS`.

## Generate

`managen mainpage [list of markdown option file names]`

This command outputs a single huge nroff file, meant to become `curl.1`. The
full curl man page.

`managen ascii [list of markdown option file names]`

This command outputs a single text file, meant to become `curl.txt`. The full
curl man page in text format, used to build `tool_hugehelp.c`.

`managen listhelp`

Generates a full `curl --help` output for all known command line options.
