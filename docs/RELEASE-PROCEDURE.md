curl release procedure - how to do a release
============================================

in the source code repo
-----------------------

- run `./scripts/copyright.pl` and correct possible omissions

- edit `RELEASE-NOTES` to be accurate

- update `docs/THANKS`

- make sure all relevant changes are committed on the master branch

- tag the git repo in this style: `git tag -a curl-7_34_0`. -a annotates the
  tag and we use underscores instead of dots in the version number. Make sure
  the tag is GPG signed (using -s).

- run `./maketgz 7.34.0` to build the release tarballs. It is important that
  you run this on a machine with the correct set of autotools etc installed
  as this is what then will be shipped and used by most users on \*nix like
  systems.

- push the git commits and the new tag

- GPG sign the 4 tarballs as `maketgz` suggests

- upload the 8 resulting files to the primary download directory

in the curl-www repo
--------------------

- edit `Makefile` (version number and date),

- edit `_newslog.html` (announce the new release) and

- edit `_changes.html` (insert changes+bugfixes from RELEASE-NOTES)

- commit all local changes

- tag the repo with the same name as used for the source repo.

- make sure all relevant changes are committed and pushed on the master branch

  (the website then updates its contents automatically)

on GitHub
---------

- edit the newly made release tag so that it is listed as the latest release

inform
------

- send an email to curl-users, curl-announce and curl-library. Insert the
  RELEASE-NOTES into the mail.

celebrate
---------

- suitable beverage intake is encouraged for the festivities

curl release scheduling
=======================

Release Cycle
-------------

We do releases every 8 weeks on Wednesdays. If critical problems arise, we can
insert releases outside of the schedule or we can move the release date - but
this is rare.

Each 8 week release cycle is split in two 4-week periods.

- During the first 4 weeks after a release, we allow new features and changes
  to curl and libcurl. If we accept any such changes, we bump the minor number
  used for the next release.

- During the second 4-week period we do not merge any features or changes, we
  then only focus on fixing bugs and polishing things to make a solid coming
  release.

- After a regular procedure-following release (made on Wednesdays), the
  feature window remains closed until the following Monday in case of special
  actions or patch releases etc.

If a future release date happens to end up on a "bad date", like in the middle
of common public holidays or when the lead release manager is away traveling,
the release date can be moved forwards or backwards a full week. This is then
advertised well in advance.

Critical problems
-----------------

We can break the release cycle and do a patch release at any point if a
critical enough problem is reported. There is no exact definition of how to
assess such criticality, but if an issue is highly disturbing or has a
security impact on a large enough share of the user population it might
qualify.

If you think an issue qualifies, bring it to the curl-library mailing list and
push for it.

Coming dates
------------

Based on the description above, here are some planned release dates (at the
time of this writing):

- March 20, 2023 (8.0.0 - curl 25 years)
- May 17, 2023
- July 19, 2023
- September 6, 2023
- November 1, 2023
- December 27, 2023
- February 21, 2024
- April 17, 2024
