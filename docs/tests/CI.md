<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Continuous Integration for curl

curl runs in many different environments, so every change is run against a
large number of test suites.

Every pull request is verified for each of the following:

- it still builds, warning-free, on Linux, macOS, Windows, BSDs, with both
  clang and gcc, autotools and cmake, out-of-tree and in-tree.
- it still builds fine on Windows with all supported MSVC versions
- it follows rudimentary code style rules
- the test suite still runs 100% fine
- the release tarball (the "dist") still works
- different TLS backends and options still compile and pass tests

If the pull-request fails one of these tests, it shows up as a red X and you
are expected to fix the problem. If you do not understand what the issue is or
have other problems to fix the complaint, just ask and other project members
can likely help out.

Consider the following table while looking at pull request failures:

| CI platform as shown in PR          | State  | What to look at next       |
| ----------------------------------- | ------ | -------------------------- |
| Linux / macOS / Windows / ...       | stable | all errors and failures    |
| Fuzzer                              | stable | fuzzing results            |
| Code analyzers                      | stable | new findings               |
| checkdocs / checksrc / dist / ...   | stable | all errors and failures    |
| AppVeyor                            | stable | all errors and failures    |
| buildbot/curl_Schannel ...          | stable | all errors and failures    |
| curl.curl (linux ...)               | stable | all errors and failures    |

Sometimes the tests fail or run slowly due to a dependency service temporarily
having issues, for example package downloads, or virtualized (non-native)
environments. Sometimes a flaky failed test may occur in any jobs.

Windows jobs have a number of flaky issues, most often, these:
- test run hanging and timing out after 20 minutes.
- test run aborting with 2304 (hex 0900) or 3840 (hex 0F00).
- test run crashing with fork errors.
- steps past the test run exiting with -1073741502 (hex C0000142).

In these cases you can just try to update your pull requests to rerun the tests
later as described below.

A detailed overview of test runs and results can be found on
[Test Clutch](https://testclutch.curl.se/).

## CI servers

Here are the different CI environments that are currently in use, and how they
are configured:

### GitHub Actions (GHA)

GitHub Actions runs the following tests:

- Tests with a variety of different compilation options, OSes, CPUs.
- Fuzz tests ([see the curl-fuzzer repo for more
  info](https://github.com/curl/curl-fuzzer)).
- Static analysis and sanitizers: clang-tidy, scan-build, address sanitizer,
  memory sanitizer, thread sanitizer, CodeQL, valgrind, torture tests.

These are each configured in different files in `.github/workflows`.

### AppVeyor CI

AppVeyor runs a variety of different Windows builds, with different compilation
options.

As of October 2025 `@bagder`, `@mback2k`, `@jay`, `@vszakats`, `@dfandrich`
and `@danielgustafsson` have administrator access to the AppVeyor CI
environment.  Additional admins/group members can be added on request.

The tests are configured in `appveyor.yml`.

### Circle CI

Circle CI runs a basic Linux test suite on Ubuntu for both x86 and ARM
processors. This is configured in `.circleci/config.yml`.

You can [view the full list of CI jobs on Circle CI's
website](https://app.circleci.com/pipelines/github/curl/curl).

`@bagder` has access to edit the "Project Settings" on that page. Additional
admins/group members can be added on request.
