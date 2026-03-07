<!-- Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al. -->
<!-- SPDX-License-Identifier: curl -->
# OPTIONS

Options start with one or two dashes. Many of the options require an
additional value next to them. If provided text does not start with a dash, it
is presumed to be and treated as a URL.

The short "single-dash" form of the options, -d for example, may be used with
or without a space between it and its value, although a space is a recommended
separator. The long double-dash form, --data for example, requires a space
between it and its value.

Short version options that do not need any additional values can be used
immediately next to each other, like for example you can specify all the
options *-O*, *-L* and *-v* at once as *-OLv*.

In general, all boolean options are enabled with --**option** and yet again
disabled with --**no-**option. That is, you use the same option name but
prefix it with `no-`. However, in this list we mostly only list and show the
--**option** version of them.

When --next is used, it resets the parser state and you start again with a
clean option state, except for the options that are global. Global options
retain their values and meaning even after --next.

If the long option name ends with an equals sign (`=`), the argument is the
text following on its right side. (Added in 8.16.0)

The first argument that is exactly two dashes (`--`), marks the end of
options; any argument after the end of options is interpreted as a URL
argument even if it starts with a dash.

curl does little to no verification of the contents of command line arguments.
Passing in "creative octets" like newlines might trigger unexpected results.

The following options are global: `%GLOBALS`.

# ALL OPTIONS
