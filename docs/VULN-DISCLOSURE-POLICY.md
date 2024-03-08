# curl vulnerability disclosure policy

This document describes how security vulnerabilities are handled in the curl
project.

## Publishing Information

All known and public curl or libcurl related vulnerabilities are listed on
[the curl website security page](https://curl.se/docs/security.html).

Security vulnerabilities **should not** be entered in the project's public bug
tracker.

## Vulnerability Handling

The typical process for handling a new security vulnerability is as follows.

No information should be made public about a vulnerability until it is
formally announced at the end of this process. That means, for example, that a
bug tracker entry must NOT be created to track the issue since that makes the
issue public and it should not be discussed on any of the project's public
mailing lists. Messages associated with any commits should not make any
reference to the security nature of the commit if done prior to the public
announcement.

- The person discovering the issue, the reporter, reports the vulnerability on
  [HackerOne](https://hackerone.com/curl). Issues filed there reach a handful
  of selected and trusted people.

- Messages that do not relate to the reporting or managing of an undisclosed
  security vulnerability in curl or libcurl are ignored and no further action
  is required.

- A person in the security team responds to the original report to acknowledge
  that a human has seen the report.

- The security team investigates the report and either rejects it or accepts
  it. See below for examples of problems that are not considered
  vulnerabilities.

- If the report is rejected, the team writes to the reporter to explain why.

- If the report is accepted, the team writes to the reporter to let them
  know it is accepted and that they are working on a fix.

- The security team discusses the problem, works out a fix, considers the
  impact of the problem and suggests a release schedule. This discussion
  should involve the reporter as much as possible.

- The release of the information should be "as soon as possible" and is most
  often synchronized with an upcoming release that contains the fix. If the
  reporter, or anyone else involved, thinks the next planned release is too
  far away, then a separate earlier release should be considered.

- Write a security advisory draft about the problem that explains what the
  problem is, its impact, which versions it affects, solutions or workarounds,
  when the release is out and make sure to credit all contributors properly.
  Figure out the CWE (Common Weakness Enumeration) number for the flaw. See
  [SECURITY-ADVISORY](https://curl.se/dev/advisory.html) for help on creating
  the advisory.

- Request a CVE Id for the issue. curl is a CNA (CVE Numbering Authority) and
  can request its own numbers.

- Update the "security advisory" with the CVE number.

- The security team commits the fix in a private branch. The commit message
  should ideally contain the CVE number. If the severity level of the issue is
  set to Low or Medium, the fix is allowed to get merged into the master
  repository via a normal PR - but without mentioning it being a security
  vulnerability.

- The monetary reward part of the bug-bounty is managed by the Internet Bug
  Bounty team and the reporter is asked to request the reward from them after
  the issue has been completely handled and published by curl.

- No more than 10 days before release, inform
  [distros@openwall](https://oss-security.openwall.org/wiki/mailing-lists/distros)
  to prepare them about the upcoming public security vulnerability
  announcement - attach the advisory draft for information with CVE and
  current patch. 'distros' does not accept an embargo longer than 14 days and
  they do not care for Windows-specific flaws.

- No more than 48 hours before the release, the private branch is merged into
  the master branch and pushed. Once pushed, the information is accessible to
  the public and the actual release should follow suit immediately afterwards.
  The time between the push and the release is used for final tests and
  reviews.

- The project team creates a release that includes the fix.

- The project team announces the release and the vulnerability to the world in
  the same manner we always announce releases. It gets sent to the
  curl-announce, curl-library and curl-users mailing lists.

- The security webpage on the website should get the new vulnerability
  mentioned.

## security (at curl dot se)

This is a private mailing list for discussions on and about curl security
issues.

Who is on this list? There are a couple of criteria you must meet, and then we
might ask you to join the list or you can ask to join it. It really is not a
formal process. We basically only require that you have a long-term presence
in the curl project and you have shown an understanding for the project and
its way of working. You must have been around for a good while and you should
have no plans of vanishing in the near future.

We do not make the list of participants public mostly because it tends to vary
somewhat over time and a list somewhere only risks getting outdated.

## Publishing Security Advisories

1. Write up the security advisory, using markdown syntax. Use the same
   subtitles as last time to maintain consistency.

2. Name the advisory file after the allocated CVE id.

3. Add a line on the top of the array in `curl-www/docs/vuln.pm`.

4. Put the new advisory markdown file in the `curl-www/docs/` directory. Add it
   to the git repository.

5. Run `make` in your local web checkout and verify that things look fine.

6. On security advisory release day, push the changes on the curl-www
   repository's remote master branch.

## HackerOne

Request the issue to be disclosed. If there are sensitive details present in
the report and discussion, those should be redacted from the disclosure. The
default policy is to disclose as much as possible as soon as the vulnerability
has been published.

## Bug Bounty

See [BUG-BOUNTY](https://curl.se/docs/bugbounty.html) for details on the
bug bounty program.

# Severity levels

The curl project's security team rates security problems using four severity
levels depending how serious we consider the problem to be. We use **Low**,
**Medium**, **High** and **Critical**. We refrain from using numerical scoring
of vulnerabilities.

When deciding severity level on a particular issue, we take all the factors
into account: attack vector, attack complexity, required privileges, necessary
build configuration, protocols involved, platform specifics and also what
effects a possible exploit or trigger of the issue can lead do, including
confidentiality, integrity or availability problems.

## Low

This is a security problem that is truly hard or unlikely to exploit or
trigger. Due to timing, platform requirements or the fact that options or
protocols involved are rare etc. [Past
example](https://curl.se/docs/CVE-2022-43552.html)

## Medium

This is a security problem that is less hard than **Low** to exploit or
trigger. Less strict timing, wider platforms availability or involving more
widely used options or protocols. A problem that usually needs something else
to also happen to become serious. [Past
example](https://curl.se/docs/CVE-2022-32206.html)

## High

This issue in itself a serious problem with real world impact. Flaws that can
easily compromise the confidentiality, integrity or availability of resources.
Exploiting or triggering this problem is not hard. [Past
example](https://curl.se/docs/CVE-2019-3822.html)

## Critical

Easily exploitable by a remote unauthenticated attacker and lead to system
compromise (arbitrary code execution) without requiring user interaction, with
a common configuration on a popular platform. This issue has few restrictions
and requirements and can be exploited easily using most curl configurations.
[Past example](https://curl.se/docs/CVE-2000-0973.html)

# Not security issues

This is an incomplete list of issues that are not considered vulnerabilities.

## Small memory leaks

We do not consider a small memory leak a security problem; even if the amount
of allocated memory grows by a small amount every now and then. Long-living
applications and services already need to have counter-measures and deal with
growing memory usage, be it leaks or just increased use. A small memory or
resource leak is then expected to *not* cause a security problem.

Of course there can be a discussion if a leak is small or not. A large leak
can be considered a security problem due to the DOS risk. If leaked memory
contains sensitive data it might also qualify as a security problem.

## Never-ending transfers

We do not consider flaws that cause a transfer to never end to be a security
problem. There are already several benign and likely reasons for transfers to
stall and never end, so applications that cannot deal with never-ending
transfers already need to have counter-measures established.

If the problem avoids the regular counter-measures when it causes a never-
ending transfer, it might be a security problem.

## Not practically possible

If the flaw or vulnerability cannot practically get executed on existing
hardware it is not a security problem.

## API misuse

If a reported issue only triggers by an application using the API in a way
that is not documented to work or even documented to not work, it is probably
not going to be considered a security problem. We only guarantee secure and
proper functionality when the APIs are used as expected and documented.

There can be a discussion about what the documentation actually means and how
to interpret the text, which might end up with us still agreeing that it is a
security problem.

## Local attackers already present

When an issue can only be attacked or misused by an attacker present on the
local system or network, the bar is raised. If a local user wrongfully has
elevated rights on your system enough to attack curl, they can probably
already do much worse harm and the problem is not really in curl.

## Experiments

Vulnerabilities in features which are off by default (in the build) and
documented as experimental, are not eligible for a reward and we do not
consider them security problems.

## URL inconsistencies

URL parser inconsistencies between browsers and curl are expected and are not
considered security vulnerabilities. The WHATWG URL Specification and RFC
3986+ (the plus meaning that it is an extended version) [are not completely
interoperable](https://github.com/bagder/docs/blob/master/URL-interop.md).

Obvious parser bugs can still be vulnerabilities of course.

## Visible command line arguments

The curl command blanks the contents of a number of command line arguments to
prevent them from appearing in process listings. It does not blank all
arguments even if some of them that are not blanked might contain sensitive
data. We consider this functionality a best-effort and omissions are not
security vulnerabilities.

 - not all systems allow the arguments to be blanked in the first place
 - since curl blanks the argument itself they area readable for a short moment
   no matter what
 - virtually every argument can contain sensitive data, depending on use
 - blanking all arguments would make it impractical for users to differentiate
   curl command lines in process listings

## Busy-loops

Busy-loops that consume 100% CPU time but eventually end (perhaps due to a set
timeout value or otherwise) are not considered security problems. Applications
are supposed to already handle situations when the transfer loop legitimately
consumes 100% CPU time, so while a prolonged such busy-loop is a nasty bug, we
do not consider it a security problem.

## Saving files

curl cannot protect against attacks where an attacker has write access to the
same directory where curl is directed to save files.

## Tricking a user to run a command line

A creative, misleading or funny looking command line is not a security
problem. The curl command line tool takes options and URLs on the command line
and if an attacker can trick the user to run a specifically crafted curl
command line, all bets are off. Such an attacker can just as well have the
user run a much worse command that can do something fatal (like
`sudo rm -rf /`).

## Terminal output and escape sequences

Content that is transferred from a server and gets displayed in a terminal by
curl may contain escape sequences or use other tricks to fool the user. This
is curl working as designed and is not a curl security problem. Escape
sequences, moving cursor, changing color etc, is also frequently used for
good. To reduce the risk of getting fooled, save files and browse them after
download using a display method that minimizes risks.
