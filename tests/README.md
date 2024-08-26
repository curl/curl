<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# The curl Test Suite

# Running

  See the "Requires to run" section for prerequisites.

  In the root of the curl repository:

    ./configure && make && make test

  To run a specific set of tests (e.g. 303 and 410):

    make test TFLAGS="303 410"

  To run the tests faster, pass the -j (parallelism) flag:

    make test TFLAGS="-j10"

  "make test" builds the test suite support code and invokes the 'runtests.pl'
  perl script to run all the tests. The value of `TFLAGS` is passed
  directly to 'runtests.pl'.

  When you run tests via make, the flags `-a` and `-s` are passed, meaning
  to continue running tests even after one fails, and to emit short output.

  If you would like to not use those flags, you can run 'runtests.pl' directly.
  You must `chdir` into the tests directory, then you can run it like so:

    ./runtests.pl 303 410

  You must have run `make test` at least once first to build the support code.

  To see what flags are available for runtests.pl, and what output it emits, run:

    man ./tests/runtests.1

  After a test fails, examine the tests/log directory for stdout, stderr, and
  output from the servers used in the test.

## Requires to run

  - perl (and a Unix-style shell)
  - python (and a Unix-style shell, for SMB and TELNET tests)
  - python-impacket (for SMB tests)
  - diff (when a test fails, a diff is shown)
  - stunnel (for HTTPS and FTPS tests)
  - OpenSSH or SunSSH (for SCP and SFTP tests)
  - nghttpx (for HTTP/2 and HTTP/3 tests)
  - An available `en_US.UTF-8` locale

### Installation of impacket

  The Python-based test servers support Python 3.

  Please install python-impacket in the correct Python environment.
  You can use pip or your OS' package manager to install 'impacket'.

  On Debian/Ubuntu the package name is 'python3-impacket'

  On FreeBSD the package name is 'py311-impacket'

  On any system where pip is available: 'python3 -m pip install impacket'

  You may also need to manually install the Python package 'six'
  as that may be a missing requirement for impacket.

## Event-based

  If curl is built with `Debug` enabled (see below), then the `runtests.pl`
  script offers a `-e` option that makes it perform *event-based*. Such tests
  invokes the curl tool with `--test-event`, a debug-only option made for this
  purpose.

  Performing event-based means that the curl tool uses the
  `curl_multi_socket_action()` API call to drive the transfer(s), instead of
  the otherwise "normal" functions it would use. This allows us to test drive
  the socket_action API. Transfers done this way should work exactly the same
  as with the non-event based API.

  To be able to use `--test-event` together with `--parallel`, curl requires
  *libuv* to be present and enabled in the build: `configure --enable-libuv`

### Port numbers used by test servers

  All test servers run on "random" port numbers. All tests should be written
  to use suitable variables instead of fixed port numbers so that test cases
  continue to work independent on what port numbers the test servers actually
  use.

  See [`FILEFORMAT`](FILEFORMAT.md) for the port number variables.

### Test servers

  The test suite runs stand-alone servers on random ports to which it makes
  requests. For SSL tests, it runs stunnel to handle encryption to the regular
  servers. For SSH, it runs a standard OpenSSH server.

  The listen port numbers for the test servers are picked randomly to allow
  users to run multiple test cases concurrently and to not collide with other
  existing services that might listen to ports on the machine.

  The HTTP server supports listening on a Unix domain socket, the default
  location is 'http.sock'.

  For HTTP/2 and HTTP/3 testing an installed `nghttpx` is used. HTTP/3
  tests check if nghttpx supports the protocol. To override the nghttpx
  used, set the environment variable `NGHTTPX`. The default can also be
  changed by specifying `--with-test-nghttpx=<path>` as argument to `configure`.

### Shell startup scripts

  Tests which use the ssh test server, SCP/SFTP tests, might be badly
  influenced by the output of system wide or user specific shell startup
  scripts, .bashrc, .profile, /etc/csh.cshrc, .login, /etc/bashrc, etc. which
  output text messages or escape sequences on user login. When these shell
  startup messages or escape sequences are output they might corrupt the
  expected stream of data which flows to the sftp-server or from the ssh
  client which can result in bad test behavior or even prevent the test server
  from running.

  If the test suite ssh or sftp server fails to start up and logs the message
  'Received message too long' then you are certainly suffering the unwanted
  output of a shell startup script. Locate, cleanup or adjust the shell
  script.

### Memory test

  The test script checks that all allocated memory is freed properly IF curl
  has been built with the `CURLDEBUG` define set. The script automatically
  detects if that is the case, and it uses the `memanalyze.pl` script to
  analyze the memory debugging output.

  Also, if you run tests on a machine where valgrind is found, the script uses
  valgrind to run the test with (unless you use `-n`) to further verify
  correctness.

  The `runtests.pl` `-t` option enables torture testing mode. It runs each
  test many times and makes each different memory allocation fail on each
  successive run. This tests the out of memory error handling code to ensure
  that memory leaks do not occur even in those situations. It can help to
  compile curl with `CPPFLAGS=-DMEMDEBUG_LOG_SYNC` when using this option, to
  ensure that the memory log file is properly written even if curl crashes.

### Debug

  If a test case fails, you can conveniently get the script to invoke the
  debugger (gdb) for you with the server running and the same command line
  parameters that failed. Just invoke `runtests.pl <test number> -g` and then
  just type 'run' in the debugger to perform the command through the debugger.

### Logs

  All logs are generated in the log/ subdirectory (it is emptied first in the
  runtests.pl script). They remain in there after a test run.

### Log Verbosity

  A curl build with `--enable-debug` offers more verbose output in the logs.
  This applies not only for test cases, but also when running it standalone
  with `curl -v`. While a curl debug built is
  ***not suitable for production***, it is often helpful in tracking down
  problems.

  Sometimes, one needs detailed logging of operations, but does not want
  to drown in output. The newly introduced *connection filters* allows one to
  dynamically increase log verbosity for a particular *filter type*. Example:

    CURL_DEBUG=ssl curl -v https://curl.se

  makes the `ssl` connection filter log more details. One may do that for
  every filter type and also use a combination of names, separated by `,` or
  space.

    CURL_DEBUG=ssl,http/2 curl -v https://curl.se

   The order of filter type names is not relevant. Names used here are
   case insensitive. Note that these names are implementation internals and
   subject to change.

   Some, likely stable names are `tcp`, `ssl`, `http/2`. For a current list,
   one may search the sources for `struct Curl_cftype` definitions and find
   the names there. Also, some filters are only available with certain build
   options, of course.

### Test input files

  All test cases are put in the `data/` subdirectory. Each test is stored in
  the file named according to the test number.

  See [`FILEFORMAT`](FILEFORMAT.md) for a description of the test case file
  format.

### Code coverage

  gcc provides a tool that can determine the code coverage figures for the
  test suite. To use it, configure curl with `CFLAGS='-fprofile-arcs
  -ftest-coverage -g -O0'`. Make sure you run the normal and torture tests to
  get more full coverage, i.e. do:

    make test
    make test-torture

  The graphical tool `ggcov` can be used to browse the source and create
  coverage reports on \*nix hosts:

    ggcov -r lib src

  The text mode tool `gcov` may also be used, but it does not handle object
  files in more than one directory correctly.

### Remote testing

  The runtests.pl script provides some hooks to allow curl to be tested on a
  machine where perl can not be run. The test framework in this case runs on
  a workstation where perl is available, while curl itself is run on a remote
  system using ssh or some other remote execution method. See the comments at
  the beginning of runtests.pl for details.

## Test case numbering

  Test cases used to be numbered by category ranges, but the ranges filled
  up. Subsets of tests can now be selected by passing keywords to the
  runtests.pl script via the make `TFLAGS` variable.

  New tests are added by finding a free number in `tests/data/Makefile.am`.

## Write tests

  Here's a quick description on writing test cases. We basically have three
  kinds of tests: the ones that test the curl tool, the ones that build small
  applications and test libcurl directly and the unit tests that test
  individual (possibly internal) functions.

### test data

  Each test has a master file that controls all the test data. What to read,
  what the protocol exchange should look like, what exit code to expect and
  what command line arguments to use etc.

  These files are `tests/data/test[num]` where `[num]` is just a unique
  identifier described above, and the XML-like file format of them is
  described in the separate [`FILEFORMAT`](FILEFORMAT.md) document.

### curl tests

  A test case that runs the curl tool and verifies that it gets the correct
  data, it sends the correct data, it uses the correct protocol primitives
  etc.

### libcurl tests

  The libcurl tests are identical to the curl ones, except that they use a
  specific and dedicated custom-built program to run instead of "curl". This
  tool is built from source code placed in `tests/libtest` and if you want to
  make a new libcurl test that is where you add your code.

### unit tests

  Unit tests are placed in `tests/unit`. There is a tests/unit/README
  describing the specific set of checks and macros that may be used when
  writing tests that verify behaviors of specific individual functions.

  The unit tests depend on curl being built with debug enabled.
