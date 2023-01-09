<!--
Copyright (C) 1998 - 2022 Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# The curl HTTPD Test Suite

This is an additional test suite using a combination of Apache httpd and nghttpx servers to perform various tests beyond the capabilities of the standard curl test suite.

# Usage

The test cases and necessary files are in `tests/httpd`. You can invoke `pytest` from there or from the top level curl checkout and it will find all tests.

```
curl> pytest
platform darwin -- Python 3.9.15, pytest-6.2.0, py-1.10.0, pluggy-0.13.1
rootdir: /Users/sei/projects/curl
collected 5 items

tests/httpd/test_01_basic.py .....                                                                                                                                                        
```

Pytest takes arguments. `-v` increases its verbosity and can be used several times. `-k <expr>` can be used to run only matching test cases. The `expr` can be something resembling a python test or just a string that needs to match test cases in their names.

```
curl> pytest -vv -k test_01_02
```

runs all test cases that have `test_01_02` in their name. This does not have to be the start of the name. 

Depending on your setup, some test cases may be skipped and appear as `s` in the output. If you run pytest verbose, it will also give you the reason for skipping.


# Prerequisites

You will need:

1. a recent Python, the `cryptography` module and, of course, `pytest`
2. a apache httpd development version. On Debian/Ubuntu, the package `apache2-dev` has this.
3. a local `curl` project build
3. optionally, a `nghttpx` with HTTP/3 enabled or h3 test cases will be skipped.

### Configuration 

Via curl's `configure` script you may specify:
 
  * `--with-test-nghttpx=<path-of-nghttpx>` if you have nghttpx to use somewhere outside your `$PATH`.
  * `--with-test-httpd=<httpd-install-path>` if you have an Apache httpd installed somewhere else. On Debian/Ubuntu it will otherwise look into `/usr/bin` and `/usr/sbin` to find those.

## Usage Tips

Several test cases are parameterized, for example with the HTTP version to use. If you want to run a test with a particular protocol only, use a command line like:

```
curl> pytest -k "test_02_06 and h2"
```

Several test cases can be repeated, they all have the `repeat` parameter. To make this work, you have to start `pytest` in the test directory itself (for some unknown reason). Like in:

```
curl/tests/tests-httpd> pytest -k "test_02_06 and h2" --repeat=100
```

which then runs this test case a hundred times. In case of flaky tests, you can make pytest stop on the first one with:

```
curl/tests/tests-httpd> pytest -k "test_02_06 and h2" --repeat=100 --maxfail=1
```

which allow you to inspect output and log files for the failed run. Speaking of log files, the verbosity of pytest is also used to collect curl trace output. If you specify `-v` three times, the `curl` command is started with `--trace`:

```
curl/tests/tests-httpd> pytest -vvv -k "test_02_06 and h2" --repeat=100 --maxfail=1
```

all of curl's output and trace file are found in `tests/tests-httpd/gen/curl`.

## Writing Tests

There is a lot of [`pytest` documentation](https://docs.pytest.org/) with examples. No use in repeating that here. Assuming you are somewhat familiar with it, it is useful how *this* general test suite is setup. Especially if you want to add test cases.

### Servers

In `conftest.py` 3 "fixtures" are defined that are used by all test cases:

1. `env`: the test environment. It is an instance of class `testenv/env.py:Env`. It holds all information about paths, availability of features (HTTP/3!), port numbers to use, domains and SSL certificates for those.
2. `httpd`: the Apache httpd instance, configured and started, then stopped at the end of the test suite. It has sites configured for the domains from `env`. It also loads a local module `mod_curltest?` and makes it available in certain locations. (more on mod_curltest below).
3. `nghttpx`: an instance of nghttpx that provides HTTP/3 support. `nghttpx` proxies those requests to the `httpd` server. In a direct mapping, so you may access all the resources under the same path as with HTTP/2. Only the port number used for HTTP/3 requests will be different.

`pytest` manages these fixture so that they are created once and terminated before exit. This means you can `Ctrl-C` a running pytest and the server will shutdown. Only when you brutally chop its head off, might there be servers left 
behind.

### Test Cases

Tests making use of these fixtures have them in their parameter list. This tells pytest that a particular test needs them, so it has to create them. Since one can invoke pytest for just a single test, it is important that a test references the ones it needs.

All test cases start with `test_` in their name. We use a double number scheme to group them. This makes it ease to run only specific tests and also give a short mnemonic to communicate trouble with others in the project. Otherwise you are free to name test cases as you think fitting.

Tests are grouped thematically in a file with a single Python test class. This is convenient if you need a special "fixture" for several tests. "fixtures" can have "class" scope.

There is a curl helper class that knows how to invoke curl and interpret its output. Among other things, it does add the local CA to the command line, so that SSL connections to the test servers are verified. Nothing prevents anyone from running curl directly, for specific uses not covered by the `CurlClient` class.

### mod_curltest

The module source code is found in `testenv/mod_curltest`. It is compiled using the `apxs` command, commonly provided via the `apache2-dev` package. Compilation is quick and done once at the start of a test run.

The module adds 2 "handlers" to the Apache server (right now). Handler are pieces of code that receive HTTP requests and generate the response. Those handlers are:

* `curltest-echo`: hooked up on the path `/curltest/echo`. This one echoes a request and copies all data from the request body to the response body. Useful for simulating upload and checking that the data arrived as intended.
* `curltest-tweak`: hooked up on the path `/curltest/tweak`. This handler is more of a Swiss army knife. It interprets parameters from the URL query string to drive its behavior.  
  * `status=nnn`: generate a response with HTTP status code `nnn`.
  * `chunks=n`: generate `n` chunks of data in the response body, defaults to 3.
  * `chunk_size=nnn`: each chunk should contain `nnn` bytes of data. Maximum is 16KB right now.
  * `chunkd_delay=duration`: wait `duration` time between writing chunks
  * `delay=duration`: wait `duration` time to send the response headers
  * `body_error=(timeout|reset)`: produce an error after the first chunk in the response body
  * `id=str`: add `str` in the response header `request-id`

`duration` values are integers, optionally followed by a unit. Units are:

  * `d`: days (probably not useful here)
  * `h`: hours
  * `mi`: minutes 
  * `s`: seconds (the default)
  * `ms`: milliseconds

As you can see, `mod_curltest`'s tweak handler allow to simulate many kinds of responses. An example of its use is `test_03_01` where responses are delayed using `chunk_delay`. This gives the response a defined duration and the test uses that to reload `httpd` in the middle of the first request. A graceful reload in httpd lets ongoing requests finish, but will close the connection afterwards and tear down the serving process. The following request need then to open a new connection. This is verified by the test case.
 






