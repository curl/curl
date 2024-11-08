---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: runtests.pl
Section: 1
Source: runtests
See-also:
 - runtests.pl
Added-in: 7.5
---

# NAME

runtests.pl - run one or more test cases

# SYNOPSIS

**runtests.pl [options] [tests]**

# DESCRIPTION

*runtests.pl* runs one, several or all the existing test cases in curl's
test suite. It is often called from the root Makefile of the curl package with
'make test'.

# TESTS

Specify which test(s) to run by specifying test numbers or keywords.

If no test number or keyword is given, all existing tests that the script can
find are considered for running. You can specify single test cases to run by
specifying test numbers space-separated, like `1 3 5 7 11`, and you can
specify a range of tests like `45 to 67`.

Specify tests to not run with a leading exclamation point, like `!66`, which
runs all available tests except number 66.

Prefix a test number with a tilde (~) to still run it, but ignore the results.

It is also possible to specify tests based on a keyword describing the test(s)
to run, like `FTPS`. The keywords are strings used in the individual tests.

You can also specify keywords with a leading exclamation point and the keyword
or phrase, like "!HTTP NTLM auth" to run all tests **except** those using this
keyword. Remember that the exclamation marks and spaces need to be quoted
somehow when entered at many command shells.

Prefix a keyword with a tilde (~) to still run it, but ignore the results.

# OUTPUT

When running without `-s` (short output), for instance when running
runtests.pl directly rather than via make, each test emits a pair of lines
like this:

    Test 0045...[simple HTTP Location: without protocol in initial URL]
    --pd---e-v- OK (45  out of 1427, remaining: 16:08, took 6.188s, duration: 00:31)

the first line contains the test number and a description. On the second line,
the characters at the beginning are flags indicating which aspects of curl's
behavior were checked by the test:

    s stdout
    r stderr
    p protocol
    d data
    u upload
    P proxy
    o output
    e exit code
    m memory
    v valgrind
    E the test was run event-based

The remainder of the second line contains the test result, current test sequence,
total number of tests to be run and an estimated amount of time to complete the
test run.

# OPTIONS

## `-a`

Continue running the rest of the test cases even if one test fails. By
default, the test script stops as soon as an error is detected.

## `-ac \<curl\>`

Provide a path to a curl binary to talk to APIs (currently only CI test APIs).

## `-am`

Display test results in automake style output (`PASS/FAIL: [number] [name]`).

## `-bundle`

Run tests via bundled test binaries. Bundled test binaries contain all tests,
and the test name passed as the first argument selects which test run.

## `-c\<curl\>`

Provide a path to a custom curl binary to run the tests with. Default is the
curl executable in the build tree.

## `-d`

Enable protocol debug: have the servers display protocol output. If used in
conjunction with parallel testing, it is difficult to associate the logs with
the specific test being run.

## `-E \<exclude_file\>`

Load the **exclude_file** with additional reasons why certain tests should be
skipped. Useful when testing with external HTTP proxies in which case some of
the tests are not appropriate.

The file contains colon-delimited lines. The first field contains the type of
exclusion, the second field contains a pattern and the final field contains
the reason why matching tests should be skipped. The exclusion types are
*keyword*, *test*, and *tool*.

## `-e` or `--test-event`

Run the test event-based (if possible). This makes runtests invoke curl with
--test-event option. This option only works if both curl and libcurl were
built debug-enabled.

## `-f`

Force the test to run even if mentioned in DISABLED.

## `-g`

Run the given test(s) with gdb. This is best used on a single test case and
curl built --disable-shared. This then fires up gdb with command line set to
run the specified test case. Simply (set a break-point and) type 'run' to
start.

## `-gl`

Run the given test(s) with lldb. This is best used on a single test case and
curl built --disable-shared. This then fires up lldb with command line set to
run the specified test case. Simply (set a break-point and) type 'run' to
start.

## `-gw`

Run the given test(s) with gdb as a windowed application.

## `-h, --help`

Displays a help text about this program's command line options.

## `-j[num]`

Spawn the given number of processes to run tests in. This defaults to 0 to run
tests serially within a single process. Using a number greater than one allows
multiple tests to run in parallel, speeding up a test run. The optimum number
is dependent on the system and set of tests to run, but 7 times the number of
CPU cores is a good figure to start with, or 1.3 times if Valgrind is in use,
or 5 times for torture tests. Enabling parallel tests is not recommended in
conjunction with the -g option.

## `-k`

Keep output and log files in log/ after a test run, even if no error was
detected. Useful for debugging.

## `-L \<file\>`

Load and execute the specified file which should contain perl code. This
option allows one to change *runtests.pl* behavior by overwriting functions
and variables and is useful when testing external proxies using curl's
regression test suite.

## `-l`

Lists all test case names.

## `-n`

Disable the check for and use of valgrind.

## `--no-debuginfod`

Delete the `DEBUGINFOD_URLS` variable if that is defined. Makes valgrind, gdb
etc not able to use this functionality.

## `-o \<variablename=value\>`

Overwrite the specified internal **variable** with **value**. Useful to change
variables that did not get a dedicated flag to change them. Check the source to
see which variables are available.

## `-P \<proxy\>`

Use the specified HTTP proxy when executing tests, even if the tests
themselves do not specify a proxy. This option allows one to test external
proxies using curl's regression test suite.

## `-p`

Prints out all files in the log directory to stdout when a test case fails.
Practical when used in the automated and distributed tests since then the
people checking the failures and the reasons for them might not have physical
access to the machine and logs.

## `-R`

Run the tests in a scrambled, or randomized, order instead of sequentially.

The random seed initially set for this is fixed per month and can be set with
*--seed*.

## `-r`

Display run time statistics. (Requires the `Perl Time::HiRes` module)

## `-rf`

Display full run time statistics. (Requires the `Perl Time::HiRes` module)

## `-rm`

Force removal of files by killing locking processes. (Windows only, requires
the **Sysinternals** `handle[64].exe` to be on PATH)

## `--repeat=[num]`

This repeats the given set of test numbers this many times. If no test numbers
are given, it repeats ALL tests this many times. It adds the new repeated
sequence at the end of the initially given one.

If **-R** option is also used, the scrambling is done after the repeats have
extended the test sequence.

## `-s`

Shorter output. Speaks less than default.

## `--seed=[num]`

When using *--shallow* or *-R* that randomize certain aspects of the behavior,
this option can set the initial seed. If not set, the random seed is set based
on the currently set local year and month and the first line of the "curl -V"
output.

## `--shallow=[num]`

Used together with **-t**. This limits the number of tests to fail in torture
mode to no more than **num** per test case. If this reduces the amount, the
script randomly discards entries to fail until the amount is **num**.

The random seed initially set for this is fixed per month and can be set with
*--seed*.

## `-t[num]`

Selects a **torture** test for the given tests. This makes runtests.pl first
run the tests once and count the number of memory allocations made. It then
reruns the test that number of times, each time forcing one of the allocations
to fail until all allocations have been tested. By setting *num* you can force
the allocation with that number to be set to fail at once instead of looping
through everyone, which is handy when debugging and then often in combination
with *-g*.

## `--test-duphandle`

Passes the `--test-duphandle` option to curl when invoked. This command line
option only exists in debug builds and runs curl normally, but duplicates the
easy handle before the transfer and use the duplicate instead of the original
handle. This verifies that the duplicate works exactly as good as the original
handle.

Because of how the curl tool uses a share object to store and keep some data,
not everything is however perfectly copied in the duplicate. In particular
HSTS data is not. A specific test case can be set to avoid using
`--test-duphandle` by disabling it on a per test basis.

## `-u`

Error instead of warning on server unexpectedly alive.

## `-v`

Enable verbose output. Speaks more than by default. If used in conjunction
with parallel testing, it is difficult to associate the logs with the specific
test being run.

## `-vc \<curl\>`

Provide a path to a custom curl binary to run when verifying that the servers
running are indeed our test servers. Default is the curl executable in the
build tree.

# RUNNING TESTS

Many tests have conditions that must be met before the test case can run fine.
They could depend on built-in features in libcurl or features present in the
operating system or even in third-party libraries that curl may or may not
use.

The test script checks most of these by itself to determine when it is safe to
attempt to run each test. Those which cannot be run due to failed requirements
are simply skipped and listed at the completion of all test cases. In some
unusual configurations, the test script cannot make the correct determination
for all tests. In these cases, the problematic tests can be skipped using the
"!keyword" skip feature documented earlier.

# WRITING TESTS

The simplest way to write test cases is to start with a similar existing test,
save it with a new number and then adjust it to fit. There is an attempt to
document the test case file format in **tests/FILEFORMAT.md**.
