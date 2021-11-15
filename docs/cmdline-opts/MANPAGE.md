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

    Short: (single letter, without dash)
    Long: (long form name, without dashes)
    Arg: (the argument the option takes)
    Magic: (description of "magic" options)
    Tags: (space separated list)
    Protocols: (space separated list for which protocols this option works)
    Added: (version number in which this was added)
    Mutexed: (space separated list of options this overrides, no dashes)
    Requires: (space separated list of features this requires, no dashes)
    See-also: (space separated list of related options, no dashes)
    Help: (short text for the --help output for this option)
    Example: (example command line, without "curl" and can use `$URL`)
    --- (end of meta-data)

### Body

The body of the description. Only refer to options with their long form option
version, like `--verbose`. The output generator will replace such with the
correct markup that shows both short and long version.

Text written within `*asterisks*` will get shown using italics. Text within
two `**asterisks**` will get shown using bold.

Text that is prefixed with a space will be treated like an "example" and will
be output in monospace.

## Header and footer

`page-header` is the file that will be output before the generated options
output for the master man page.

`page-footer` is appended after all the individual options.

## Generate

`./gen.pl mainpage`

This command outputs a single huge nroff file, meant to become `curl.1`. The
full curl man page.

`./gen.pl listhelp`

Generates a full `curl --help` output for all known command line options.
