# curl man page generator

This is the curl man page generator. It generates a single nroff man page
output from the set of sources files in this directory.

There is one source file for each supported command line option. The format is
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
    Mutexed: (space separated list of options this overrides)
    Requires: (space separated list of features this option requres)
    See-also: (space separated list of related options)
    --- (end of meta-data)

### Body

The body of the description. Only refer to options with their long form option
version, like --verbose. The output generator will replace such with the
correct markup that shows both short and long version.

## Header

`page-header` is the nroff formatted file that will be output before the
generated options output.

## Generate

`perl gen.pl`

This command outputs an nroff file, meant to become `curl.1`. The full curl
man page.
