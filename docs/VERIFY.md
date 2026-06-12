<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Verify

Do not trust, verify!

## Signed releases

Every curl release is shipped as a set of tarballs. They all have the exact
same content but use different archivers, visible by the different file
extensions used.

Each tarball is signed by the curl release manager Daniel. The digital
signatures for each tarball are always provided. The digital signatures can be
used to verify that the tarballs were produced by Daniel.

If the curl website were breached and fake curl releases were
provided, they could be detected using these signatures.

Daniel's public GPG key: [27ED EAF2 2F3A BCEB 50DB 9A12 5CC9 08FD B71E 12C2](https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x27edeaf22f3abceb50db9a125cc908fdb71e12c2)

## Reproducible releases

The curl project ships *reproducible releases*. This means that everyone is
able - and encouraged - to independently verify the contents of every curl
release. Verify that it contains exactly the bits that are supposed to be in
the release and nothing extra.

The curl releases are generated using a Docker image to make it easy to get an
identical setup. To verify an existing curl release, we provide a convenient
script that generates a new curl release from source code and then compares
this newly generated release tarball with the tarball file you downloaded from
curl.se.

Invoke it like this:

    ./scripts/verify-release curl-8.19.0.tar.xz

By verifying the release tarballs, you verify that Daniel does not infect the
release on purpose or involuntarily because of anything malicious running in
his setup.

### Verify the verify

Of course you should not blindly trust the verification script. It is short
and simple and should be quick to verify. Or you write your own script that
you trust, to do the same job.

## Source code

How do you then verify that what is in git is fine to build a product from?

In the curl project we verify the source code in multiple ways, and one way to
gain trust is to verify and review our testing procedures.

- we have a consistent code style (invalid style causes errors)

- we ban and avoid a number of "sensitive" and "hard-to-use" C functions (use
  of such functions causes errors)

- we have a ceiling for complexity in functions to keep them easy to follow,
  read and understand (failing to do so causes errors)

- we review all pull requests before merging, both with humans and with bots. We
  link back commits to their origin pull requests in commit messages.

- we ban use of "binary blobs" in git to not provide means for malicious
  actors to bundle encrypted payloads (trying to include a blob causes errors)

- we actively avoid base64 encoded chunks as they too could function as ways
  to obfuscate malicious contents

- we ban most uses of UTF-8 in code and documentation to avoid easily mixed
  up Unicode characters that look like other characters. (adding Unicode
  characters causes errors)

- we document everything to make it clear how things are supposed to work. No
  surprises. Lots of documentation is tested and verified in addition to
  spellchecks and consistent wording.

- we have thousands of tests and we add test cases for (ideally) every
  functionality. Finding "white spots" and adding coverage is a top priority.
  curl runs on countless operating systems, CPU architectures and you can
  build curl in billions of different configuration setups: not every
  combination is practically possible to test

- we build curl and run tests in over two hundred CI jobs that are run for
  every commit and every PR. We do not merge commits that have unexplained
  test failures.

- we build curl in CI with the most picky compiler options enabled and we
  never allow compiler warnings to linger. We always use `-Werror` that
  converts warnings to errors and fail the builds.

- we run all tests using valgrind and several combinations of sanitizers to
  find and reduce the risk for memory problems, undefined behavior and
  similar

- we run all tests as "torture tests", where each test case is rerun to have
  every invoked fallible function call fail once each, to make sure curl
  never leaks memory or crashes due to this.

- we run fuzzing on curl: non-stop as part of Google's OSS-Fuzz project, but
  also briefly as part of the CI setup for every commit and PR

- we make sure that the CI jobs we have for curl never "write back" to curl.
  They access the source repository read-only and even if they would be
  breached, they cannot infect or taint source code.

- we run `zizmor` and other code analyzer tools on the CI job config scripts
  to reduce the risk of us running or using insecure CI jobs.

- we are committed to always fix reported vulnerabilities in the following
  release. Security problems never linger around once they have been
  reported.

- we document everything and every detail about all curl vulnerabilities ever
  reported

- our commitment to never breaking ABI or API allows all users to easily
  upgrade to new releases. This enables users to run recent security-fixed
  versions instead of legacy insecure versions.

- our code has been audited several times by external security experts, and
  the few issues that have been detected in those were immediately addressed

- Two-factor authentication on GitHub is mandatory for all committers
