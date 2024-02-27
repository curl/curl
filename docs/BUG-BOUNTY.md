# The curl bug bounty

The curl project runs a bug bounty program in association with
[HackerOne](https://www.hackerone.com) and the [Internet Bug
Bounty](https://internetbugbounty.org).

## How does it work?

Start out by posting your suspected security vulnerability directly to [curl's
HackerOne program](https://hackerone.com/curl).

After you have reported a security issue, it has been deemed credible, and a
patch and advisory has been made public, you may be eligible for a bounty from
this program. See the [Security Process](https://curl.se/dev/secprocess.html)
document for how we work with security issues.

## What are the reward amounts?

The curl project offers monetary compensation for reported and published
security vulnerabilities. The amount of money that is rewarded depends on how
serious the flaw is determined to be.

Since 2021, the Bug Bounty is managed in association with the Internet Bug
Bounty and they set the reward amounts. If it would turn out that they set
amounts that are way lower than we can accept, the curl project intends to
"top up" rewards.

In 2022, typical "Medium" rated vulnerabilities have been rewarded 2,400 USD
each.

## Who is eligible for a reward?

Everyone and anyone who reports a security problem in a released curl version
that has not already been reported can ask for a bounty.

Dedicated - paid for - security audits that are performed in collaboration
with curl developers are not eligible for bounties.

Vulnerabilities in features that are off by default and documented as
experimental are not eligible for a reward.

The vulnerability has to be fixed and publicly announced (by the curl project)
before a bug bounty is considered.

Once the vulnerability has been published by curl, the researcher can request
their bounty from the [Internet Bug Bounty](https://hackerone.com/ibb).

Bounties need to be requested within twelve months from the publication of the
vulnerability.

The curl security team reserves themselves the right to deny or allow bug
bounty payouts on its own discretion. There is no appeals process.

## Product vulnerabilities only

This bug bounty only concerns the curl and libcurl products and thus their
respective source codes - when running on existing hardware. It does not
include curl documentation, curl websites, or other curl related
infrastructure.

The curl security team is the sole arbiter if a reported flaw is subject to a
bounty or not.

## How are vulnerabilities graded?

The grading of each reported vulnerability that makes a reward claim is
performed by the curl security team. The grading is based on the CVSS (Common
Vulnerability Scoring System) 3.0.

## How are reward amounts determined?

The curl security team gives the vulnerability a score or severity level, as
mentioned above. The actual monetary reward amount is decided and paid by the
Internet Bug Bounty..

## Regarding taxes, etc. on the bounties

In the event that the individual receiving a bug bounty needs to pay taxes on
the reward money, the responsibility lies with the receiver. The curl project
or its security team never actually receive any of this money, hold the money,
or pay out the money.
