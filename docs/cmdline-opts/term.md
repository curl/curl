---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: term
Help: Add terminal metadata to the default User-Agent
Protocols: HTTP
Category: http
Added: 8.21.0
Multi: boolean
See-also:
  - user-agent
Example:
  - --term $URL
---

# `--term`

Add terminal metadata to curl's built-in default User-Agent header. When this
option is used, curl appends a comment with terminal metadata derived from the
current environment and terminal state.

The generated fields are:

## `term`

The sanitized value of `TERM`, when set.

## `cols`

The terminal width. curl first checks `COLUMNS`, and if it is unset or invalid,
it tries to query the terminal size.

## `lines`

The terminal height. curl first checks `LINES`, and if it is unset or invalid,
it tries to query the terminal size.

## `attached`

Whether curl has a terminal attached on stdin. This field is always sent as
either `true` or `false` when `--term` is enabled.

## `color`

The detected color level. curl reports `truecolor` when `COLORTERM` is
`truecolor` or `24bit`, `256` when `TERM` contains `256color`, `mono` when
`TERM` is `dumb`, and `16` when `COLORTERM` is set to any other non-empty
value.

## `graphics`

The sanitized value of `TERM_GRAPHICS`, when set. This can be used to advertise
terminal image protocol support, for example `sixel` or `kitty`.

## `lang`

The sanitized value of `LANG`, when set.

Unsafe characters are replaced with `_`, and repeated replacement characters
are collapsed.

Example:

```text
curl/8.21.0 (term=xterm; attached=true; graphics=sixel)
```

This option is opt-in and only changes curl's built-in default User-Agent.
If `--user-agent` is used, that value is left untouched. Use `--no-term` to
disable it again.

Empty environment-derived fields are omitted, but `attached` is always
included.

This option is experimental.
