---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: fetch
Title: testfetch.pl
Section: 1
Source: testfetch
See-also:
  - runtests.pl
Added-in: 7.11.2
---

# NAME

testfetch.pl - (automatically) test fetch

# SYNOPSIS

**testfetch.pl [options] [dir] \> output**

# DESCRIPTION

_testfetch_ is the master script to use for automatic distributed testing of
fetch from git or daily snapshots. It is written for the purpose of being run
from a crontab job or similar at a regular interval. The output is suitable to
be mailed to **fetch-autocompile@haxx.se** to be dealt with automatically (make
sure the subject includes the word "autobuild" as the mail gets silently
discarded otherwise). The most current build status (with a reasonable
backlog) is published on the fetch site, at https://curl.se/dev/builds.html

_options_ may be omitted. See _--setup_ for what happens then.

_dir_ is a fetch source directory, possibly a daily snapshot one. Using this
makes _testfetch_ skip the _autoreconf_ stage and thus it removes the
dependency on automake, autoconf, libtool, GNU m4 and possibly a few other
things.

_testfetch_ runs `autoreconf` (or similar), configure, builds fetch and libfetch
in a separate build directory and then runs `make test` to test the fresh
build.

# OPTIONS

## `--configure=[options]`

Configure options passed to configure.

## `--crosscompile`

``
This is a cross-compile. Makes _testfetch_ skip a few things.

## `--desc=[desc]`

Description of your test system. Displayed on the build summary page on the
website.

## `--email=[email]`

Set email address to report as. Displayed in the build logs on the site.

## `--mktarball=[command]`

Generic command to run after completed test.

## `--name=[name]`

Set name to report as. Displayed in the build summary on the site.

## `--nobuildconf`

Do not run autoreconf. Useful when many builds use the same source tree, as
then only one need to do this. Also, if multiple processes run tests
simultaneously on the same source tree (like several hosts on a NFS mounted
directory), simultaneous autoreconf invokes may cause problems. (Added in
7.14.1)

## `--nogitpull`

Do not update from git even though it is a git tree. Useful to still be able
to test even though your network is down, or similar.

## `--runtestopts=[options]`

Options that is passed to the runtests script. Useful for disabling valgrind
by force, and similar.

## `--setup=[filename]`

filename to read setup from (deprecated). The old style of providing info. If
info is missing when _testfetch_ is started, it prompts you and then stores the
info in a 'setup' file, which it looks for on each invoke. Use _--name_,
_--email_, _--configure_ and _--desc_ instead.

## `--target=[your os]`

Specify your target environment. Recognized strings include `vc`, `mingw32`,
and `borland`.

# INITIAL SETUP

First, make a checkout from git (or you write a script that downloads daily
snapshots automatically):

    $ mkdir fetch-testing
    $ cd fetch-testing
    $ git clone https://github.com/curl/curl.git

With the fetch sources checked out, or downloaded, you can start testing right
away. If you want to use _testfetch_ without command line arguments and to have
it store and remember the config in its 'setup' file, then start it manually
now and fill in the answers to the questions it prompts you for:

    $ ./fetch/tests/testfetch

Now you are ready to go. If you let the script run, it performs a full cycle
and spit out lots of output. Mail us that output as described above.

# CRONTAB EXAMPLE

The crontab could include something like this:

    # autobuild fetch:
    0 4 * * * cd fetch-testing && ./testit.sh

Where `testit.sh` is a shell script that could look similar to this:

    mail="mail -s autobuild fetch-autocompile@haxx.se"
    name="--name=whoami"
    email="--email=iamme@nowhere"
    desc='"--desc=supermachine Turbo 2000"'
    testprog="perl ./fetch/tests/testfetch.pl $name $email $desc"
    opts1="--configure=--enable-debug"
    opts2="--configure=--enable-ipv6"

    # run first test
    $testprog $opts1 | $mail

    # run second test
    $testprog $opts2 | $mail
