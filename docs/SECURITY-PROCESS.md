curl security process
=====================

This document describes how security vulnerabilities should be handled in the
curl project.

Publishing Information
----------------------

All known and public curl or libcurl related vulnerabilities are listed on
[the curl website security page](https://curl.se/docs/security.html).

Security vulnerabilities **should not** be entered in the project's public bug
tracker.

Vulnerability Handling
----------------------

The typical process for handling a new security vulnerability is as follows.

No information should be made public about a vulnerability until it is
formally announced at the end of this process. That means, for example, that a
bug tracker entry must NOT be created to track the issue since that will make
the issue public and it should not be discussed on any of the project's public
mailing lists. Also messages associated with any commits should not make any
reference to the security nature of the commit if done prior to the public
announcement.

- The person discovering the issue, the reporter, reports the vulnerability on
  [https://hackerone.com/curl](https://hackerone.com/curl). Issues filed there
  reach a handful of selected and trusted people.

- Messages that do not relate to the reporting or managing of an undisclosed
  security vulnerability in curl or libcurl are ignored and no further action
  is required.

- A person in the security team responds to the original report to acknowledge
  that a human has seen the report.

- The security team investigates the report and either rejects it or accepts
  it.

- If the report is rejected, the team writes to the reporter to explain why.

- If the report is accepted, the team writes to the reporter to let him/her
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
  Figure out the CWE (Common Weakness Enumeration) number for the flaw.

- Request a CVE number from
  [HackerOne](https://docs.hackerone.com/programs/cve-requests.html)

- Update the "security advisory" with the CVE number.

- The security team commits the fix in a private branch. The commit message
  should ideally contain the CVE number.

- The security team also decides on and delivers a monetary reward to the
  reporter as per the bug-bounty policies.

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

- The security web page on the website should get the new vulnerability
  mentioned.

security (at curl dot se)
------------------------------

This is a private mailing list for discussions on and about curl security
issues.

Who is on this list? There are a couple of criteria you must meet, and then we
might ask you to join the list or you can ask to join it. It really is not a
formal process. We basically only require that you have a long-term presence
in the curl project and you have shown an understanding for the project and
its way of working. You must have been around for a good while and you should
have no plans of vanishing in the near future.

We do not make the list of participants public mostly because it tends to vary
somewhat over time and a list somewhere will only risk getting outdated.

Publishing Security Advisories
------------------------------

1. Write up the security advisory, using markdown syntax. Use the same
   subtitles as last time to maintain consistency.

2. Name the advisory file after the allocated CVE id.

3. Add a line on the top of the array in `curl-www/docs/vuln.pm'.

4. Put the new advisory markdown file in the curl-www/docs/ directory. Add it
   to the git repo.

5. Run `make` in your local web checkout and verify that things look fine.

6. On security advisory release day, push the changes on the curl-www
   repository's remote master branch.

Hackerone
---------

Request the issue to be disclosed. If there are sensitive details present in
the report and discussion, those should be redacted from the disclosure. The
default policy is to disclose as much as possible as soon as the vulnerability
has been published.

Bug Bounty
----------

See [BUG-BOUNTY](https://curl.se/docs/bugbounty.html) for details on the
bug bounty program.
