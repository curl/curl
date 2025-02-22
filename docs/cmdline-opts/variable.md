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
  - --variable name=smith --expand-url "$URL/{{name}}"
---

# `--variable`

Set a variable with `name=content` or `name@file` (where `file` can be stdin
if set to a single dash (`-`)). The name is a case sensitive identifier that
must consist of no other letters than a-z, A-Z, 0-9 or underscore. The
specified content is then associated with this identifier.

Setting the same variable name again overwrites the old contents with the new.

The contents of a variable can be referenced in a later command line option
when that option name is prefixed with `--expand-`, and the name is used as
`{{name}}`.

--variable can import environment variables into the name space. Opt to either
require the environment variable to be set or provide a default value for the
variable in case it is not already set.

--variable %name imports the variable called `name` but exits with an error if
that environment variable is not already set. To provide a default value if
the environment variable is not set, use --variable %name=content or
--variable %name@content. Note that on some systems - but not all -
environment variables are case insensitive.

Added in curl 8.12.0: you can get a byte range from the source by appending
`[start-end]` to the variable name, where *start* and *end* are byte offsets
to include from the contents. For example, asking for offset "2-10" means
offset two to offset ten, inclusive, resulting in 9 bytes in total. `2-2`
means a single byte at offset 2. Not providing a second number implies to the
end of data. The start offset cannot be larger than the end offset. Asking for
a range that is outside of the file size makes the variable contents empty.
For example, getting the first one hundred bytes from a given file:

    curl --variable "fraction[0-99]@filename"

Given a byte range that has no data results in an empty string. Asking for a
range that is larger than the content makes curl use the piece of the data
that exists.

To assign a variable using contents from another variable, use
--expand-variable. Like for example assigning a new variable using contents
from two other:

    curl --expand-variable "user={{firstname}} {{lastname}}"

When expanding variables, curl supports a set of functions that can make the
variable contents more convenient to use. You apply a function to a variable
expansion by adding a colon and then list the desired functions in a
comma-separated list that is evaluated in a left-to-right order. Variable
content holding null bytes that are not encoded when expanded, causes an
error.

Available functions:

## `trim`

removes all leading and trailing white space.

Example:

    curl --expand-url https://example.com/{{var:trim}}

## `json`

outputs the content using JSON string quoting rules.

Example:

    curl --expand-data {{data:json}} https://example.com

## `url`

shows the content URL (percent) encoded.

Example:

    curl --expand-url https://example.com/{{path:url}}

## `b64`

expands the variable base64 encoded

Example:

    curl --expand-url https://example.com/{{var:b64}}

## `64dec`

decodes a base64 encoded character sequence. If the sequence is not possible
to decode, it instead outputs `[64dec-fail]`

Example:

    curl --expand-url https://example.com/{{var:64dec}}

(Added in 8.13.0)
