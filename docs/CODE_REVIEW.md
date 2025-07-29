<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# How to do code reviews for curl

Anyone and everyone is encouraged and welcome to review code submissions in
curl. This is a guide on what to check for and how to perform a successful
code review.

## All submissions should get reviewed

All pull requests and patches submitted to the project should be reviewed by
at least one experienced curl maintainer before that code is accepted and
merged.

## Let the tools and tests take the first rounds

On initial pull requests, let the tools and tests do their job first and then
start out by helping the submitter understand the test failures and tool
alerts.

## How to provide feedback to author

Be nice. Ask questions. Provide examples or suggestions of improvements.
Assume the best intentions. Remember language barriers.

All first-time contributors can become regulars. Let's help them go there.

## Is this a change we want?

If this is not a change that seems to be aligned with the project's path
forward and as such cannot be accepted, inform the author about this sooner
rather than later. Do it gently and explain why and possibly what could be
done to make it more acceptable.

## API/ABI stability or changed behavior

Changing the API and the ABI may be fine in a change but it needs to be done
deliberately and carefully. If not, a reviewer must help the author to realize
the mistake.

curl and libcurl are similarly strict on not modifying existing behavior. API
and ABI stability is not enough, the behavior should also remain intact as far
as possible.

## Code style

Most code style nits are detected by checksrc but not all. Only leave remarks
on style deviation once checksrc does not find anymore.

Minor nits from fresh submitters can also be handled by the maintainer when
merging, in case it seems like the submitter is not clear on what to do. We
want to make the process fun and exciting for new contributors.

## Encourage consistency

Make sure new code is written in a similar style as existing code. Naming,
logic, conditions, etc.

## Are pointers always non-NULL?

If a function or code rely on pointers being non-NULL, take an extra look if
that seems to be a fair assessment.

## Asserts

Conditions that should never be false can be verified with `DEBUGASSERT()`
calls to get caught in tests and debugging easier, while not having an impact
on final or release builds.

## Memory allocation

Can the mallocs be avoided? Do not introduce mallocs in any hot paths. If
there are (new) mallocs, can they be combined into fewer calls?

Are all allocations handled in error paths to avoid leaks and crashes?

## Thread-safety

We do not like static variables as they break thread-safety and prevent
functions from being reentrant.

## Should features be `#ifdef`ed?

Features and functionality may not be present everywhere and should therefore
be `#ifdef`ed. Additionally, some features should be possible to switch on/off
in the build.

Write `#ifdef`s to be as little of a "maze" as possible.

## Does it look portable enough?

curl runs "everywhere". Does the code take a reasonable stance and enough
precautions to be possible to build and run on most platforms?

Remember that we live by C89 restrictions.

## Tests and testability

New features should be added in conjunction with one or more test cases.
Ideally, functions should also be written so that unit tests can be done to
test individual functions.

## Documentation

New features or changes to existing functionality **must** be accompanied by
updated documentation. Submitting that in a separate follow-up pull request is
not OK. A code review must also verify that the submitted documentation update
matches the code submission.

English is not everyone's first language, be mindful of this and help the
submitter improve the text if it needs a rewrite to read better.

## Code should not be hard to understand

Source code should be written to maximize readability and be easy to
understand.

## Functions should not be large

A single function should never be large as that makes it hard to follow and
understand all the exit points and state changes. Some existing functions in
curl certainly violate this ground rule but when reviewing new code we should
propose splitting into smaller functions.

## Duplication is evil

Anything that looks like duplicated code is a red flag. Anything that seems to
introduce code that we *should* already have or provide needs a closer check.

## Sensitive data

When credentials are involved, take an extra look at what happens with this
data. Where it comes from and where it goes.

## Variable types differ

`size_t` is not a fixed size. `time_t` can be signed or unsigned and have
different sizes. Relying on variable sizes is a red flag.

Also remember that endianness and >= 32-bit accesses to unaligned addresses
are problematic areas.

## Integer overflows

Be careful about integer overflows. Some variable types can be either 32-bit
or 64-bit. Integer overflows must be detected and acted on *before* they
happen.

## Dangerous use of functions

Maybe use of `realloc()` should rather use the dynbuf functions?

Do not allow new code that grows buffers without using dynbuf.

Use of C functions that rely on a terminating zero must only be used on data
that really do have a null-terminating zero.

## Dangerous "data styles"

Make extra precautions and verify that memory buffers that need a terminating
zero always have exactly that. Buffers *without* a null-terminator must not be
used as input to string functions.

# Commit messages

Tightly coupled with a code review is making sure that the commit message is
good. It is the responsibility of the person who merges the code to make sure
that the commit message follows our standard (detailed in the
[CONTRIBUTE](https://curl.se/dev/contribute.html) document). This includes
making sure the PR identifies related issues and giving credit to reporters
and helpers.
