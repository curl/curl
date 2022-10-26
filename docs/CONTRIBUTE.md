# Contributing to the curl project

This document is intended to offer guidelines on how to best contribute to the
curl project. This concerns new features as well as corrections to existing
flaws or bugs.

## Join the Community

Skip over to [https://curl.se/mail/](https://curl.se/mail/) and join
the appropriate mailing list(s). Read up on details before you post
questions. Read this file before you start sending patches. We prefer
questions sent to and discussions being held on the mailing list(s), not sent
to individuals.

Before posting to one of the curl mailing lists, please read up on the
[mailing list etiquette](https://curl.se/mail/etiquette.html).

We also hang out on IRC in #curl on libera.chat

If you are at all interested in the code side of things, consider clicking
'watch' on the [curl repo on GitHub](https://github.com/curl/curl) to be
notified of pull requests and new issues posted there.

## License and copyright

When contributing with code, you agree to put your changes and new code under
the same license curl and libcurl is already using unless stated and agreed
otherwise.

If you add a larger piece of code, you can opt to make that file or set of
files to use a different license as long as they do not enforce any changes to
the rest of the package and they make sense. Such "separate parts" can not be
GPL licensed (as we do not want copyleft to affect users of libcurl) but they
must use "GPL compatible" licenses (as we want to allow users to use libcurl
properly in GPL licensed environments).

When changing existing source code, you do not alter the copyright of the
original file(s). The copyright will still be owned by the original creator(s)
or those who have been assigned copyright by the original author(s).

By submitting a patch to the curl project, you are assumed to have the right
to the code and to be allowed by your employer or whatever to hand over that
patch/code to us. We will credit you for your changes as far as possible, to
give credit but also to keep a trace back to who made what changes. Please
always provide us with your full real name when contributing,

## What To Read

Source code, the man pages, the [INTERNALS
document](https://curl.se/dev/internals.html),
[TODO](https://curl.se/docs/todo.html),
[KNOWN_BUGS](https://curl.se/docs/knownbugs.html) and the [most recent
changes](https://curl.se/dev/sourceactivity.html) in git. Just lurking on
the [curl-library mailing
list](https://curl.se/mail/list.cgi?list=curl-library) will give you a
lot of insights on what's going on right now. Asking there is a good idea too.

## Write a good patch

### Follow code style

When writing C code, follow the
[CODE_STYLE](https://curl.se/dev/code-style.html) already established in
the project. Consistent style makes code easier to read and mistakes less
likely to happen. Run `make checksrc` before you submit anything, to make sure
you follow the basic style. That script does not verify everything, but if it
complains you know you have work to do.

### Non-clobbering All Over

When you write new functionality or fix bugs, it is important that you do not
fiddle all over the source files and functions. Remember that it is likely
that other people have done changes in the same source files as you have and
possibly even in the same functions. If you bring completely new
functionality, try writing it in a new source file. If you fix bugs, try to
fix one bug at a time and send them as separate patches.

### Write Separate Changes

It is annoying when you get a huge patch from someone that is said to fix 511
odd problems, but discussions and opinions do not agree with 510 of them - or
509 of them were already fixed in a different way. Then the person merging
this change needs to extract the single interesting patch from somewhere
within the huge pile of source, and that creates a lot of extra work.

Preferably, each fix that corrects a problem should be in its own patch/commit
with its own description/commit message stating exactly what they correct so
that all changes can be selectively applied by the maintainer or other
interested parties.

Also, separate changes enable bisecting much better for tracking problems
and regression in the future.

### Patch Against Recent Sources

Please try to get the latest available sources to make your patches against.
It makes the lives of the developers so much easier. The best is if you get
the most up-to-date sources from the git repository, but the latest release
archive is quite OK as well.

### Documentation

Writing docs is dead boring and one of the big problems with many open source
projects. But someone's gotta do it. It makes things a lot easier if you
submit a small description of your fix or your new features with every
contribution so that it can be swiftly added to the package documentation.

The documentation is always made in man pages (nroff formatted) or plain
ASCII files. All HTML files on the website and in the release archives are
generated from the nroff/ASCII versions.

### Test Cases

Since the introduction of the test suite, we can quickly verify that the main
features are working as they are supposed to. To maintain this situation and
improve it, all new features and functions that are added need to be tested
in the test suite. Every feature that is added should get at least one valid
test case that verifies that it works as documented. If every submitter also
posts a few test cases, it will not end up as a heavy burden on a single person!

If you do not have test cases or perhaps you have done something that is hard
to write tests for, do explain exactly how you have otherwise tested and
verified your changes.

## Submit Your Changes

### How to get your changes into the main sources

Ideally you file a [pull request on
GitHub](https://github.com/curl/curl/pulls), but you can also send your plain
patch to [the curl-library mailing
list](https://curl.se/mail/list.cgi?list=curl-library).

If you opt to post a patch on the mailing list, chances are someone will
convert it into a pull request for you, to have the CI jobs verify it proper
before it can be merged. Be prepared that some feedback on the proposed change
might then come on GitHub.

Your change will be reviewed and discussed and you will be expected to correct
flaws pointed out and update accordingly, or the change risks stalling and
eventually just getting deleted without action. As a submitter of a change,
you are the owner of that change until it has been merged.

Respond on the list or on GitHub about the change and answer questions and/or
fix nits/flaws. This is important. We will take lack of replies as a sign that
you are not anxious to get your patch accepted and we tend to simply drop such
changes.

### About pull requests

With GitHub it is easy to send a [pull
request](https://github.com/curl/curl/pulls) to the curl project to have
changes merged.

We strongly prefer pull requests to mailed patches, as it makes it a proper
git commit that is easy to merge and they are easy to track and not that easy
to lose in the flood of many emails, like they sometimes do on the mailing
lists.

Every pull request submitted will automatically be tested in several different
ways. [See the CI document for more
information](https://github.com/curl/curl/blob/master/tests/CI.md).

Sometimes the tests fail due to a dependency service temporarily being offline
or otherwise unavailable, e.g. package downloads. In this case you can just
try to update your pull requests to rerun the tests later as described below.

You can update your pull requests by pushing new commits or force-pushing
changes to existing commits. Force-pushing an amended commit without any
actual content changed also allows you to retrigger the tests for that commit.

When you adjust your pull requests after review, consider squashing the
commits so that we can review the full updated version more easily.

A pull request sent to the project might get labeled `needs-votes` by a
project maintainer. This label means that in addition to meeting all other
checks and qualifications this pull request must also receive more "votes" of
user support. More signs that people want this to happen. It could be in the
form of messages saying so, or thumbs-up reactions on GitHub.

### Making quality changes

Make the patch against as recent source versions as possible.

If you have followed the tips in this document and your patch still has not
been incorporated or responded to after some weeks, consider resubmitting it
to the list or better yet: change it to a pull request.

### Commit messages

A short guide to how to write commit messages in the curl project.

    ---- start ----
    [area]: [short line describing the main effect]
           -- empty line --
    [full description, no wider than 72 columns that describe as much as
    possible as to why this change is made, and possibly what things
    it fixes and everything else that is related]
           -- empty line --
    [Closes/Fixes #1234 - if this closes or fixes a github issue]
    [Bug: URL to source of the report or more related discussion]
    [Reported-by: John Doe - credit the reporter]
    [whatever-else-by: credit all helpers, finders, doers]
    ---- stop ----

The first line is a succinct description of the change:

 - use the imperative, present tense: "change" not "changed" nor "changes"
 - do not capitalize first letter
 - no dot (.) at the end

The `[area]` in the first line can be `http2`, `cookies`, `openssl` or
similar. There's no fixed list to select from but using the same "area" as
other related changes could make sense.

Do not forget to use commit --author="" if you commit someone else's work, and
make sure that you have your own user and email setup correctly in git before
you commit

### Write Access to git Repository

If you are a frequent contributor, you may be given push access to the git
repository and then you will be able to push your changes straight into the git
repo instead of sending changes as pull requests or by mail as patches.

Just ask if this is what you would want. You will be required to have posted
several high quality patches first, before you can be granted push access.

### How To Make a Patch with git

You need to first checkout the repository:

    git clone https://github.com/curl/curl.git

You then proceed and edit all the files you like and you commit them to your
local repository:

    git commit [file]

As usual, group your commits so that you commit all changes at once that
constitute a logical change.

Once you have done all your commits and you are happy with what you see, you
can make patches out of your changes that are suitable for mailing:

    git format-patch remotes/origin/master

This creates files in your local directory named `NNNN-[name].patch` for each
commit.

Now send those patches off to the curl-library list. You can of course opt to
do that with the 'git send-email' command.

### How To Make a Patch without git

Keep a copy of the unmodified curl sources. Make your changes in a separate
source tree. When you think you have something that you want to offer the
curl community, use GNU diff to generate patches.

If you have modified a single file, try something like:

    diff -u unmodified-file.c my-changed-one.c > my-fixes.diff

If you have modified several files, possibly in different directories, you
can use diff recursively:

    diff -ur curl-original-dir curl-modified-sources-dir > my-fixes.diff

The GNU diff and GNU patch tools exist for virtually all platforms, including
all kinds of Unixes and Windows.

### Useful resources
 - [Webinar on getting code into cURL](https://www.youtube.com/watch?v=QmZ3W1d6LQI)

## Update copyright and license information

There is a CI job called **REUSE compliance / check** that will run on every
pull request and commit to verify that the *REUSE state* of all files are
still fine.

This means that all files need to have their license and copyright information
clearly stated. Ideally by having the standard curl source code header, with
an accurate copyright year range and the SPDX-License-Identifier included. If
the header does not work, you can use a smaller header or add the information
for a specific file to the `.reuse/dep5` file.

We update copyright year ranges to end on the year of the most recent change
of the individual file.

You can manually verify the copyright and compliance status by running the
`./scripts/copyright.pl` script in the root of the git repository.
