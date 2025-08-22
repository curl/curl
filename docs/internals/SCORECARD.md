<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# scorecard.py

This is an internal script in `tests/http/scorecard.py` used for testing
curl's performance in a set of cases. These are for exercising parts of
curl/libcurl in a reproducible fashion to judge improvements or detect
regressions. They are not intended to represent real world scenarios
as such.

This script is not part of any official interface and we may
change it in the future according to the project's needs.

## setup

When you are able to run curl's `pytest` suite, scorecard should work
for you as well. They start a local Apache httpd or Caddy server and
invoke the locally build `src/curl` (by default).

## invocation

A typical invocation for measuring performance of HTTP/2 downloads would be:

```
curl> python3 tests/http/scorecard.py -d h2
```

and this prints a table with the results. The last argument is the protocol to test and
it can be `h1`, `h2` or `h3`. You can add `--json` to get results in JSON instead of text.

Help for all command line options are available via:

```
curl> python3 tests/http/scorecard.py -h
```

## scenarios

Apart from `-d/--downloads` there is `-u/--uploads` and `-r/--requests`. These are run with
a variation of resource sizes and parallelism by default. You can specify these in some way
if you are just interested in a particular case.

For example, to run downloads of a 1 MB resource only, 100 times with at max 6 parallel transfers, use:

```
curl> python3 tests/http/scorecard.py -d --download-sizes=1mb --download-count=100 --download-parallel=6 h2
```

Similar options are available for uploads and requests scenarios.

## sockd

If you have configured curl with `--with-test-danted=<danted-path>` for a
`dante-server` installed on your system, you can provide the scorecard
with arguments `--socks4` or `--socks5` to test performance with a SOCKS proxy
involved. (Note: this does not work for HTTP/3)

## dtrace

With the `--dtrace` option, scorecard produces a dtrace sample of the user stacks in `tests/http/gen/curl/curl.user_stacks`. On many platforms, `dtrace` requires **special permissions**. It is therefore invoked via `sudo` and you should make sure that sudo works for the run without prompting for a password.

Note: the file is the trace of the last curl invocation by scorecard. Use the parameters to narrow down the runs to the particular case you are interested in.

## flame graphs

With the excellent [Flame Graph](https://github.com/brendangregg/FlameGraph) by Brendan Gregg, scorecard can turn the `dtrace` samples into an interactive SVG. Set the environment variable `FLAMEGRAPH` to the location of your clone of that project and invoked scorecard with the `--flame` option. Like

```
curl> FLAMEGRAPH=/Users/sei/projects/FlameGraph python3 tests/http/scorecard.py \
   -r --request-count=50000 --request-parallels=100 --samples=1 --flame h2
```
and the SVG of the run is in `tests/http/gen/curl/curl.flamegraph.svg`. You can open that in Firefox and zoom in/out of stacks of interest.

Note: as with `dtrace`, the flame graph is for the last invocation of curl done by scorecard.
