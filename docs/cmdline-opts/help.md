---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: help
Arg: <category>
Short: h
Help: Get help for commands
Category: important curl
Added: 4.0
Multi: custom
See-also:
  - verbose
Example:
  - --help all
---

# `--help`

Usage help. This lists all curl command line options within the given
**category**.

If no argument is provided, curl displays only the most important command line
arguments.

For category **all**, curl displays help for all options.

If **category** is specified, curl displays all available help categories.
