<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# curl vulnerability disclosure policy

This document describes how security vulnerabilities are handled in the curl
project.

There is no bug bounty and the curl project never offers rewards for reported
vulnerabilities.

## Information

All known and public curl or libcurl related vulnerabilities are listed on
[the curl website security page](https://curl.se/docs/security.html).

## Vulnerability Handling

The typical process for handling a new security vulnerability is as follows.

### Report

The person discovering the issue, the reporter, reports the vulnerability on
[HackerOne](https://hackerone.com/curl). Issues filed there reach a handful of
selected and trusted people.

Alternatively, a reporter may submit the report [directly on
GitHub](https://github.com/curl/curl/issue) if the severity is deemed less
than HIGH.

When communicating in the curl project, please explain your issues or
improvements briefly and clearly in your own human voice. Do not lazily paste
massive, AI-generated explanations; it is your responsibility to invest a few
extra minutes into making your message digestible. The maintainers review
submissions constantly, and clear writing reduces their daily burden and
friction.

The curl project cannot handle vulnerability reports sent to us over email. We
lose track of the reports. We cannot easily disclose them. Please do not send
us reports over email.

Messages that do not relate to the reporting or managing of an undisclosed
security vulnerability in curl or libcurl are ignored and no further action is
required.

### Confirming it

Someone in the security team responds to the original report to acknowledge
that a human has seen the report.

The curl security team investigates the claims in the report and either
rejects it or accepts it. See below for examples of problems that are not
considered vulnerabilities.

If the report is rejected, the team to explains why.

If the report is confirmed and acknowledged, the team writes to the reporter
to let them know it is.

### Low/Medium severity issues are public

For all reported vulnerabilities with severity LOW or MEDIUM, the reporter
will be asked to instead submit it publicly in the [curl issue
tracker](https://github.com/curl/curl/issues) on GitHub, or even better as a
[pull-request](https://github.com/curl/curl/pulls). These issues are then not
managed any further privately on HackerOne.

If in doubt of the severity, starting out on HackerOne is fine.

Asking the reporter to instead submit the issue on GitHub does not necessarily
imply that we accept it as a vulnerability, but we might. It might also be
"just a bug". It should be treated as a "let's continue the conversation over
there in the public" request.

If a reported issue is deemed to be severity HIGH or CRITICAL, it should
remain on HackerOne to be handled privately until a pending releases can be
shipped that inclueds a fix for the problem.

### Fixing

A vulnerability is a bug. We fix all known bugs. If the report is handled on
GitHub, the whole world can and is encouraged to participate in the discussion
and bugfixing. For privately reported vulnerabilities, only the reporter and
the curl security team can participate in the discussion and fixing.

A fix for the reported vulnerability together with extensive information about
the problem should be released "as soon as possible" - most often synchronized
with an upcoming release.

If the reporter, or anyone else involved, thinks the next planned release is
too far away (and the severity is HIGH or CRITICAL), an earlier release should
be considered.

If the severity level of the issue is set to LOW or MEDIUM, the fix is worked
on and merged into the master repository via a normal pull-request.

Vulnerabilities at severity HIGH or CRITICAL get fixed and worked on in a
private branch to reduce the impact and risk for existing users. Only the
reported and the curl security team can access this.

### Documenting

Write a security advisory draft about the problem that explains what the
problem is, its impact, which versions it affects, solutions or workarounds,
when the release is out and make sure to credit all contributors properly.
Figure out the CWE (Common Weakness Enumeration) number for the flaw. See
[SECURITY-ADVISORY](https://curl.se/dev/advisory.html) for help on creating
the advisory.

Request a CVE Id for the issue. curl is a CNA (CVE Numbering Authority) and
can request its own numbers.

Update the "security advisory" with the CVE number.

### Release preparations

No more than seven days before release, inform
[distros@openwall](https://oss-security.openwall.org/wiki/mailing-lists/distros)
to prepare them about the upcoming public security vulnerability
announcement - attach the advisory draft for information with CVE and current
patch. 'distros' does not accept an embargo longer than 7 days and they do not
care for Windows-specific flaws.

No more than 48 hours before the release, the private branch is merged into
the master branch and pushed (if one was used). Once pushed, the information
is accessible to the public and the actual release should follow suit
immediately afterwards. The time between the push and the release is used for
final tests and reviews.

### Release

The project team creates a release that includes the fix.

The project team announces the release and the vulnerability to the world in
the same manner we always announce releases. It gets sent to the
curl-announce, curl-library and curl-users mailing lists.

The security webpage on the website should get the new vulnerability
mentioned.

## security (at curl dot se)

This is a private mailing list to reach the curl security team. It shall not
be used for vulnerability reporting.

We do not make the list of list participants public mostly because it tends to
vary somewhat over time and a list somewhere only risks getting outdated.

## Disclose the report

For transparency and in the spirit of complete openness, *all* vulnerability
reports submitted to the project, valid or not, should and will be disclosed
and made public once they have been handled.

# Severity levels

The curl project's security team rates security problems using four severity
levels depending on how serious we consider the problem to be. We use **Low**,
**Medium**, **High** and **Critical**. We refrain from using numerical scoring
of vulnerabilities.

We do not support CVSS as a method to grade security vulnerabilities, so we do
not set them for CVE records published by the curl project. We believe CVSS is
a broken system that often does not properly evaluate to suitable severity
levels that reflect all dimensions and factors involved. Other organizations
however set and provide CVSS scores for curl vulnerabilities. You need to
decide for yourself if you believe they know enough about the subjects
involved to make reasonable assessments. Deciding between four different
severity levels is hard enough for us.

When deciding severity level on a particular issue, we take all the factors
into account: attack vector, attack complexity, required privileges, necessary
build configuration, protocols involved, platform specifics and also what
effects a possible exploit or trigger of the issue can lead to, including
confidentiality, integrity or availability problems.

## Low

This is a security problem that is truly hard or unlikely to exploit or
trigger. Due to timing, platform requirements or the fact that options or
protocols involved are rare etc. [Past
example](https://curl.se/docs/CVE-2022-43552.html)

Issues that are likely to be detected by basic testing are likely to not be
considered more severe than **Low**. Users that do not test cannot be expected
to have secure setups to begin with.

## Medium

This is a security problem that is less hard than **Low** to exploit or
trigger. Less strict timing, wider platform availability or involving more
widely used options or protocols. A problem that usually needs something else
to also happen to become serious. [Past
example](https://curl.se/docs/CVE-2022-32206.html)

## High

This issue is in itself a serious problem with real world impact. Flaws that
can easily compromise the confidentiality, integrity or availability of
resources. Exploiting or triggering this problem is not hard. [Past
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
applications and services already need to have countermeasures and deal with
growing memory usage, be it leaks or increased use. A small memory or resource
leak is then expected to *not* cause a security problem.

Of course there can be a discussion if a leak is small or not. A large leak
can be considered a security problem due to the DOS risk. If leaked memory
contains sensitive data it might also qualify as a security problem.

## Never-ending transfers

We do not consider flaws that cause a transfer to never end to be a security
problem. There are already several benign and likely reasons for transfers to
stall and never end, so applications that cannot deal with never-ending
transfers already need to have counter-measures established.

Well-known attacks, like
[Slowloris](https://en.wikipedia.org/wiki/Slowloris_(cyber_attack)), that send
partial requests are usually not considered a flaw. If the problem bypasses
the regular counter-measures and it causes a never-ending transfer, it might
be a security problem.

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

## Debug & Experiments

Vulnerabilities in features which are off by default (in the build) and
documented as experimental, or exist only in debug mode, are not considered
security problems.

The same applies to scripts and software which are not installed by default
through the make install rule.

## Test code

curl has an extensive test suite with lots of code written specifically to
exercise and verify curl, libcurl and specific internal functions. The test
code and its associated test servers are *not* intended for production use.
They are not secure, you should not assume otherwise and must not report about
security problems in those.

## URL inconsistencies

URL parser inconsistencies between browsers and curl are expected and are not
considered security vulnerabilities. The WHATWG URL Specification and RFC
3986+ (the plus meaning that it is an extended version) [are not completely
interoperable](https://github.com/bagder/docs/blob/master/URL-interop.md).

Obvious parser bugs can still be vulnerabilities of course.

## Visible command line arguments

The curl command blanks the contents of a number of command line arguments to
prevent them from appearing in process listings. It does not blank all
arguments, even though some that are not blanked might contain sensitive
data. We consider this functionality a best-effort and omissions are not
security vulnerabilities.

- not all systems allow the arguments to be blanked in the first place
- since curl blanks the argument itself they are readable for a short moment
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
command line, all bets are off. Such an attacker can already have the user run
a much worse command that can do something fatal (like `sudo rm -rf /`).

## Terminal output and escape sequences

Content that is transferred from a server and gets displayed in a terminal by
curl may contain escape sequences or use other tricks to fool the user. This
is curl working as designed and is not a curl security problem. Escape
sequences, moving cursor, changing color etc, is also frequently used for
good. To reduce the risk of getting fooled, save files and browse them after
download using a display method that minimizes risks.

## NULL dereferences and crashes

If a malicious server can trigger a NULL dereference in curl or otherwise
cause curl to crash (and nothing worse), chances are big that we do not
consider that a security problem.

Malicious servers can already cause considerable harm and denial of service
like scenarios without having to trigger such code paths. For example by
stalling, being terribly slow or by delivering enormous amounts of data.
Additionally, applications are expected to handle "normal" crashes without
that being the end of the world.

There need to be more and special circumstances to treat such problems as
security issues.

## Legacy dependencies

Problems that can be triggered only by the use of a *legacy dependency* are
not considered security problems.

A *legacy dependency* is here defined as:

- the legacy version was released over ten years ago AND

- the legacy version is no longer in use by any existing still supported
  operating system or distribution AND

- there are modern versions of equivalent or better functionality offered and
  in common use

## Weak algorithms required for functionality

curl supports several algorithms that are considered weak, like DES and MD5.
These algorithms are still not curl security vulnerabilities or security
problems as they are only used when the users explicitly ask for their use by
using the protocols or options that require the use of those algorithms.

When servers upgrade to use secure alternatives, curl users should use those
options/protocols.

## CRLF in data

curl makes barely any claims of *cleaning* input or rejecting invalid data. A
user that uses a curl feature can send in *creative* sequences that include
carriage-return (CR) or line-feed (LF) characters.

Therefore, we reject the idea of *CRLF injection* as a security problem. It is
a *feature* that users can send creative byte sequences. If users do not want
to send such octets, they are in control and should avoid sending such bytes
to curl.

For example, a user might pass in a username that looks like
`Mr[CR][LF]Smith`. It may cause some minor havoc in the protocol handling,
depending on what protocol is used.

## Non-released code

Only curl releases are ever considered *secure*. Between releases, we are
under development and then we may have code present in the git repository that
is insecure, but without those flaws being considered as vulnerabilities.
Another reason we strongly suggest you only use curl release versions in
production.

Unreleased code may also contain fixes to problems that were present in the
most recent release.

# curl major incident response

Vulnerability disclosure manages the full life cycle of a vulnerability
affecting curl - where the **curl-security** team privately engages with
reporters coordinating on embargo and eventual release of security fixes.

For most vulnerabilities (even critical vulnerabilities) this is the
normal _'mode'_ of incident response.

A **major incident** is defined as something that has much larger scope and
impact on users and developers of curl.

A major incident usually encompasses one or more of the following:
* broad and deep impact on developers, distros and users
* high visibility
* remote code execution
* exploit readily available
* critical curl infrastructure compromised
* time sensitive
* premature disclosure (e.g. embargo broken)

A major incident is declared only when it is deemed that the normal
vulnerability disclosure process is not sufficient.

The curl **major incident** process is as follows:

## Major incident begins

Only a member of the **curl-security** team can declare a **major incident**
via any or all of the following communication channels:

* **irc**: channel #curl on the network [Libera.Chat](https://libera.chat/)
* **mailing-lists**:
  * curl-announce
  * curl-users
  * curl-distros
* **website**: [curl.se](https://curl.se/)

This declaration may also be transmitted via other channels, though the
above are considered official channels.

The veracity of such a communication can be verified by consulting two
or more **curl-security** team members.

This announcement nominates, from **curl-security** team, the following
roles:

* **incident lead** - Coordinates technical efforts
* **communication lead** - Single point of public contact

It is likely that our
[BDFL](https://en.wikipedia.org/wiki/Benevolent_dictator_for_life) occupies
one of these roles, though this plan does not depend on it.

A declaration may also contain more detailed information but as we honor
embargoes and vulnerability disclosure throughout this process, it may also
contain a brief notification that a **major incident** is occurring.

## Major incident ongoing

During the incident - all press, media, legal or commercial entities should
contact communication lead (security@curl.se).

Existing **curl-security** team internal communication channels are used
for all internal communication.

Existing vulnerability disclosure process are followed for any embargoes
and fixes.

Where possible, public communications are provided:
* regular communication from communication lead (for example daily update)
* asynchronous communication from incident lead

* Delivered to the aforementioned curl communication channels.

A log is kept of all external and internal communication.

Once fixes have been released we may provide a more detailed postmortem and
overall timeline of events.

## Major incident ends

Both the incident and communication leads declare when a **major incident**
has finished.

Any notices are removed and a return to normal vulnerability disclosure
process.
