---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: help
Arg: <subject>
Short: h
Help: Get help for commands
Category: important curl
Added: 4.0
Multi: custom
See-also:
  - verbose
Example:
  - --help all
  - --help --insecure
  - --help -f
---

# `--help`

Usage help. Provide help for the subject given as an optional argument.

If no argument is provided, curl displays the most important command line
arguments.

The argument can either be a **category** or a **command line option**. When a
category is provided, curl shows all command line options within the given
category. Specify category `all` to list all available options.

If `category` is specified, curl displays all available help categories.

If the provided subject is instead an existing command line option, specified
either in its short form with a single dash and a single letter, or in the
long form with two dashes and a longer name, curl displays a help text for
that option in the terminal.

The help output is extensive for some options.

If the provided command line option is not known, curl says so.
