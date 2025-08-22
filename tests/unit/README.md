<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Unit tests

The goal is to add tests for *all* functions in libcurl. If functions are too
big and complicated, we should split them into smaller and testable ones.

## Build Unit Tests

`./configure --enable-debug` is required for the unit tests to build. To
enable unit tests, there is a separate static libcurl built that is used
exclusively for linking unit test programs. Just build everything as normal,
and then you can run the unit test cases as well.

## Run Unit Tests

Unit tests are run as part of the regular test suite. If you have built
everything to run unit tests, to can do 'make test' at the root level. Or you
can `cd tests` and `make` and then invoke individual unit tests with
`./runtests.pl NNNN` where `NNNN` is the specific test number.

## Debug Unit Tests

If a specific test fails you get told. The test case then has output left in
the %LOGDIR subdirectory, but most importantly you can re-run the test again
using gdb by doing `./runtests.pl -g NNNN`. That is, add a `-g` to make it
start up gdb and run the same case using that.

## Write Unit Tests

We put tests that focus on an area or a specific function into a single C
source file. The source file should be named `unitNNNN.c` where `NNNN` is a
previously unused number.

Add your test to `tests/unit/Makefile.inc` (if it is a unit test). Add your
test data filename to `tests/data/Makefile.am`

You also need a separate file called `tests/data/testNNNN` (using the same
number) that describes your test case. See the test1300 file for inspiration
and the `tests/FILEFORMAT.md` documentation.

For the actual C file, here's a simple example:
~~~c
    #include "unitcheck.h"

    #include "a libcurl header.h" /* from the lib dir */

    static CURLcode test_unit9998(const char *arg)
    {
      UNITTEST_BEGIN_SIMPLE

      /* here you start doing things and checking that the results are good */

      fail_unless( size == 0 , "initial size should be zero" );
      fail_if( head == NULL , "head should not be initiated to NULL" );

      /* you end the test code like this: */

      UNITTEST_END_SIMPLE
    }
~~~

Here's an example using optional initialization and cleanup:
~~~c
    #include "unitcheck.h"

    #include "a libcurl header.h" /* from the lib dir */

    static CURLcode t9999_setup(void)
    {
      /* whatever you want done first */
      return CURLE_OK;
    }

    static void t9999_stop(void)
    {
      /* done before shutting down and exiting */
    }

    static CURLcode test_unit9999(const char *arg)
    {
      UNITTEST_BEGIN(t9999_setup())

      /* here you start doing things and checking that the results are good */

      fail_unless( size == 0 , "initial size should be zero" );
      fail_if( head == NULL , "head should not be initiated to NULL" );

      /* you end the test code like this: */

      UNITTEST_END(t9999_stop())
    }
~~~
