<!--
  Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

  SPDX-License-Identifier: curl
-->

# curl man page generator

This is the curl man page generator. It generates a single nroff man page
output from the set of sources files in this directory.

There is one source file for each supported command line option. The output
gets `page-header` prepended and `page-footer` appended. The format is
described below.

## Option files

Each command line option is described in a file named `<long name>.d`, where
option name is written without any prefixing dashes. Like the file name for
the -v, --verbose option is named `verbose.d`.

Each file has a set of meta-data and a body of text.

### Meta-data

    Added: (version number in which this was added)
    Arg: (the argument the option takes)
    c: (copyright line)
    Example: (example command line, without "curl" and can use `$URL`)
    Experimental: yes (if so)
    Help: (short text for the --help output for this option)
    Long: (long form name, without dashes)
    Magic: (description of "magic" options)
    Multi: single/append/boolean/mutex/custom (if used more than once)
    Mutexed: (space separated list of options this overrides, no dashes)
    Protocols: (space separated list for which protocols this option works)
    Requires: (space separated list of features this requires, no dashes)
    Scope: global (if the option is global)
    See-also: (space separated list of related options, no dashes)
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

## Header and footer

`page-header` is the file that is output before the generated options output
for the master man page.

`page-footer` is appended after all the individual options.

## Generate

`./gen.pl mainpage`

This command outputs a single huge nroff file, meant to become `curl.1`. The
full curl man page.

`./gen.pl listhelp`

Generates a full `curl --help` output for all known command line options.
