<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Continuous Integration for curl

curl runs in many different environments, so every change is run against a
large number of test suites.

Every pull request is verified for each of the following:

 - ... it still builds, warning-free, on Linux and macOS, with both
   clang and gcc
 - ... it still builds fine on Windows with several MSVC versions
 - ... it still builds with cmake on Linux, with gcc and clang
 - ... it follows rudimentary code style rules
 - ... the test suite still runs 100% fine
 - ... the release tarball (the "dist") still works
 - ... it builds fine in-tree as well as out-of-tree
 - ... code coverage does not shrink drastically
 - ... different TLS backends still compile and pass tests

If the pull-request fails one of these tests, it shows up as a red X and you
are expected to fix the problem. If you do not understand when the issue is or
have other problems to fix the complaint, just ask and other project members
can likely help out.

Consider the following table while looking at pull request failures:

 | CI platform as shown in PR          | State  | What to look at next       |
 | ----------------------------------- | ------ | -------------------------- |
 | CI / fuzzing                        | stable | fuzzing results            |
 | CI / macos ...                      | stable | all errors and failures    |
 | FreeBSD FreeBSD: ...                | stable | all errors and failures    |
 | LGTM analysis: Python               | stable | new findings               |
 | LGTM analysis:  C/C++               | stable | new findings               |
 | buildbot/curl_Schannel_ ...         | stable | all errors and failures    |
 | AppVeyor                            | flaky  | all errors and failures    |
 | curl.curl (linux ...)               | stable | all errors and failures    |
 | curl.curl (windows ...)             | flaky  | repetitive errors/failures |

Sometimes the tests fail due to a dependency service temporarily being offline
or otherwise unavailable, for example package downloads. In this case you can
just try to update your pull requests to rerun the tests later as described
below.

## CI servers

Here are the different CI environments that are currently in use, and how they
are configured:

### GitHub Actions

GitHub Actions runs the following tests:

- macOS tests with a variety of different compilation options
- Fuzz tests ([see the curl-fuzzer repo for more
  info](https://github.com/curl/curl-fuzzer)).

These are each configured in different files in `.github/workflows`.

### Azure

Not used anymore.

### AppVeyor

AppVeyor runs a variety of different Windows builds, with different compilation
options.

As of November 2021 `@bagder`, `@mback2k`, `@jay`, `@vszakats`, `@dfandrich`
and `@danielgustafsson` have administrator access to the AppVeyor CI
environment.  Additional admins/group members can be added on request.

The tests are configured in `appveyor.yml`.

### Zuul

Not used anymore.

### Circle CI

Circle CI runs a basic Linux test suite on Ubuntu for both x86 and ARM
processors. This is configured in `.circleci/config.yml`.

You can [view the full list of CI jobs on Circle CI's
website](https://app.circleci.com/pipelines/github/curl/curl).

`@bagder` has access to edit the "Project Settings" on that page. Additional
admins/group members can be added on request.

### Cirrus CI

Not used anymore.
