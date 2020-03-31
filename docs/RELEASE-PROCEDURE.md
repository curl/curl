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

- run "./maketgz 7.34.0" to build the release tarballs. It is important that
  you run this on a machine with the correct set of autotools etc installed
  as this is what then will be shipped and used by most users on \*nix like
  systems.

- push the git commits and the new tag

- gpg sign the 4 tarballs as maketgz suggests

- upload the 8 resulting files to the primary download directory

in the curl-www repo
--------------------

- edit `Makefile` (version number and date),

- edit `_newslog.html` (announce the new release) and

- edit `_changes.html` (insert changes+bugfixes from RELEASE-NOTES)

- commit all local changes

- tag the repo with the same name as used for the source repo.

- make sure all relevant changes are committed and pushed on the master branch

  (the web site then updates its contents automatically)

on github
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

Coming dates
------------

Based on the description above, here are some planned release dates (at the
time of this writing):

- March 4, 2020 (7.69.0)
- April 29, 2020
- June 24, 2020
- August 19, 2020
- October 14, 2020
- December 9, 2020
- February 3, 2021

The above (and more) curl-related dates are published in
[iCalendar format](https://calendar.google.com/calendar/ical/c9u5d64odop9js55oltfarjk6g%40group.calendar.google.com/public/basic.ics)
as well.
