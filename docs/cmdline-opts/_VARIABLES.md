<!-- Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al. -->
<!-- SPDX-License-Identifier: curl -->
# VARIABLES
curl supports command line variables (added in 8.3.0). Set variables with
--variable name=content or --variable name@file (where `file` can be stdin if
set to a single dash (-)).

Variable contents can be expanded in option parameters using `{{name}}` if the
option name is prefixed with `--expand-`. This gets the contents of the
variable `name` inserted, or a blank if the name does not exist as a
variable. Insert `{{` verbatim in the string by prefixing it with a backslash,
like `\{{`.

You access and expand environment variables by first importing them. You
select to either require the environment variable to be set or you can provide
a default value in case it is not already set. Plain `--variable %name`
imports the variable called `name` but exits with an error if that environment
variable is not already set. To provide a default value if it is not set, use
`--variable %name=content` or `--variable %name@content`.

Example. Get the USER environment variable into the URL, fail if USER is not
set:

    --variable '%USER'
    --expand-url = "https://example.com/api/{{USER}}/method"

When expanding variables, curl supports a set of functions that can make the
variable contents more convenient to use. It can trim leading and trailing
white space with `trim`, it can output the contents as a JSON quoted string
with `json`, URL encode the string with `url`, base64 encode it with `b64` and
base64 decode it with `64dec`. To apply functions to a variable expansion, add
them colon separated to the right side of the variable. Variable content
holding null bytes that are not encoded when expanded causes an error.

Example: get the contents of a file called $HOME/.secret into a variable
called "fix". Make sure that the content is trimmed and percent-encoded when
sent as POST data:

    --variable %HOME
    --expand-variable fix@{{HOME}}/.secret
    --expand-data "{{fix:trim:url}}"
    https://example.com/

Command line variables and expansions were added in 8.3.0.
