<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Continuous Integration for curl

Curl runs in many different environments, so every change is run against a large
number of test suites.

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

If the pull-request fails one of these tests, it will show up as a red X and
you are expected to fix the problem. If you do not understand when the issue is
or have other problems to fix the complaint, just ask and other project
members will likely be able to help out.

Consider the following table while looking at pull request failures:

 | CI platform as shown in PR          | State  | What to look at next       |
 | ----------------------------------- | ------ | -------------------------- |
 | CI / codeql                         | stable | quality check results      |
 | CI / fuzzing                        | stable | fuzzing results            |
 | CI / macos ...                      | stable | all errors and failures    |
 | Code scanning results / CodeQL      | stable | quality check results      |
 | FreeBSD FreeBSD: ...                | stable | all errors and failures    |
 | LGTM analysis: Python               | stable | new findings               |
 | LGTM analysis:  C/C++               | stable | new findings               |
 | buildbot/curl_winssl_ ...           | stable | all errors and failures    |
 | AppVeyor                            | flaky  | all errors and failures    |
 | curl.curl (linux ...)               | stable | all errors and failures    |
 | curl.curl (windows ...)             | flaky  | repetitive errors/failures |
 | CodeQL                              | stable | new findings               |

Sometimes the tests fail due to a dependency service temporarily being offline
or otherwise unavailable, for example package downloads. In this case you can
just try to update your pull requests to rerun the tests later as described
below.

## CI servers

Here are the different CI environments that are currently in use, and how they
are configured:

### GitHub Actions

GitHub Actions runs the following tests:

- Mac OS tests with a variety of different compilation options
- Fuzz tests ([see tests/fuzz/README for
    more info](https://github.com/curl/curl/blob/master/tests/fuzz/README)).
- Curl compiled using the Rust TLS backend with Hyper
- CodeQL static analysis

These are each configured in different files in `.github/workflows`.

### Azure

The following tests are run in Microsoft Azure CI environment:

- Ubuntu tests with a variety of different compilation options.
- Windows tests with a variety of different compilation options.

These are all configured in `.azure-pipelines.yml`.

As of November 2021 `@bagder` and `@mback2k` are the only people with
administrator access to the Azure CI environment. Additional admins/group
members can be added on request.

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

Cirrus CI runs a basic test suite on FreeBSD and Windows. This is configured in
`.cirrus.yml`.

You can [view the full list of CI jobs on Cirrus CI's
website](https://cirrus-ci.com/github/curl/curl).

`@bagder` has access to edit the "Project Settings" on that page. Additional
admins/group members can be added on request.
