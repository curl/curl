---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: variable
Arg: <[%]name=text/@file>
Help: Set variable
Category: curl
Added: 8.3.0
Multi: append
See-also:
  - config
Example:
  - --variable name=smith $URL
---

# `--variable`

Set a variable with "name=content" or "name@file" (where "file" can be stdin
if set to a single dash (-)). The name is a case sensitive identifier that
must consist of no other letters than a-z, A-Z, 0-9 or underscore. The
specified content is then associated with this identifier.

Setting the same variable name again overwrites the old contents with the new.

The contents of a variable can be referenced in a later command line option
when that option name is prefixed with "--expand-", and the name is used as
"{{name}}" (without the quotes).

--variable can import environment variables into the name space. Opt to either
require the environment variable to be set or provide a default value for the
variable in case it is not already set.

--variable %name imports the variable called 'name' but exits with an error if
that environment variable is not already set. To provide a default value if
the environment variable is not set, use --variable %name=content or
--variable %name@content. Note that on some systems - but not all -
environment variables are case insensitive.

When expanding variables, curl supports a set of functions that can make the
variable contents more convenient to use. You apply a function to a variable
expansion by adding a colon and then list the desired functions in a
comma-separated list that is evaluated in a left-to-right order. Variable
content holding null bytes that are not encoded when expanded, causes an
error.

Available functions:

## trim
removes all leading and trailing white space.

## json
outputs the content using JSON string quoting rules.

## url
shows the content URL (percent) encoded.

## b64
expands the variable base64 encoded
