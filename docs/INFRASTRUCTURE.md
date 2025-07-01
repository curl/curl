<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Infrastructure in the curl project

Overview of infrastructure we maintain, host and run in the project for the
project.

## git repository

Since 2010, the main curl git repository has been hosted by GitHub, available
at https://github.com/curl/curl.

We also use the issue tracker, pull requests and discussions on GitHub.

curl has an "enterprise account" on GitHub and is an "organization" on the
site.

We accept sponsorship via GitHub Sponsors.

## CI services

For every pull request and git push to the master repository, a number of
build and testing jobs are run on a set of different CI services. The exact
services vary over time. GitHub Actions and AppVeyor are the primary ones
these days.

## Test Clutch

A [Test Clutch](https://github.com/dfandrich/testclutch) instance generates
regular reports on curl CI test results at https://testclutch.curl.se/ as well
as writing comments on curl pull requests whose tests have failed. The jobs
are hosted on a Virtuozzo Application Platform PaaS instance and is managed by
Dan Fandrich. The configuration code is available and managed at
https://github.com/dfandrich/testclutch-curl-web

## Autobuilds

The curl autobuild system is a set of scripts that build and test curl and
send all output logs back to the autobuild server. The results are
continuously collected and visualized on the curl website at
<https://curl.se/dev/builds.html>.

The autobuild system and server is maintained by Daniel Stenberg.

## OSS-Fuzz

Google runs the [OSS-Fuzz](https://google.github.io/oss-fuzz/) project which
also runs fuzzing on curl code, non-stop, in their infrastructure and they
send us emails in the rare instances they actually find something.

OSS-Fuzz notifies those that are members in the "curl team". Any curl
maintainer who wants to is welcome to participate. It requires a Google
account.

## Coverity

We regularly run our code through the [Coverity static code
analyzer](https://scan.coverity.com/) thanks to them offering this service to
us for free.

## CodeSonar

[CodeSonar](https://codesecure.com/our-products/codesonar/) analyzes the curl
source code daily and emails Daniel Stenberg whenever it finds suspected
problems in the source code. I hope and expect that we can invite other
maintainers to access these reports soon.

## Domain names

The project runs services and website using a few different curl related
domain names, including `curl.se` and `curl.dev`. Daniel Stenberg owns these
domain names.

Until a few years ago, the curl website was present at `curl.haxx.se`. The
`haxx.se` domain is owned by Haxx AB, administrated by Daniel Stenberg. The
curl.haxx.se name is meant to keep working and be redirecting to curl.se for
the foreseeable future.

## Websites

The main curl website at `curl.se` is maintained by curl maintainers and the
content is available and managed at https://github.com/curl/curl-www. The site
updates from git and runs make every 20 minutes. Any change pushed to git can
thus take up to 20 minutes until it takes effect on the origin server.

The content on `curl.dev` is available and managed at
https://github.com/curl/curl.dev/

The content on `everything-curl.dev` is available and managed at
https://github.com/curl/everything-curl/

The machine hosting the website contents for these three sites is owned by
Haxx AB and is primarily managed by Daniel Stenberg (co-owner of the Haxx
company). The machine is physically located in Sweden.

curl release tarballs are hosted on https://curl.se/download.html. They are
uploaded there at release-time by the release manager.

curl-for-win downloads are hosted on https://curl.se/windows and are uploaded
to the server by Viktor Szakats.

curl-for-QNX downloads are hosted on <https://curl.se/qnx> and are uploaded to
the server by Daniel Stenberg.

Daily release tarball-like snapshots are generated automatically and are
provided for download at <https://curl.se/snapshots/>.

CA certificate bundles are extracted from the Firefox source code, hosted by
Mozilla and converted to PEM file format and is offered for download. The
conversion checks for updates daily. The bundle is provided for download at
<https://curl.se/docs/caextract.html>.

There is an automated "download check bot" that runs twice daily to scan for
available curl downloads to populate the curl download page appropriately with
the correct updated information. The bot uses URLs and patterns for all
download packages and is maintained in a database, maintained by Daniel
Stenberg and Dan Fandrich.

The TLS certificate for the origin curl web server is automatically updated
from Let's Encrypt.

## CDN

Fastly runs the Content Delivery Network (CDN) that fronts all the curl
websites. The CDN caches content that it gets from the origin server.
Recently, roughly 99.99% of web requests are satisfied by the CDN without
having to reach the origin.

The CDN caches different content at different lengths depending on the
content-type. The caching thus adds to the time for a change to have an effect
on the site from the moment it gets pushed to the git repository.

Using this setup, we provide four IPv4 addresses and eight IPv6 addresses for
anycast access to the site. Should be snappy from virtually everywhere across
the globe.

The CDN servers support HTTP/1, HTTP/2 and HTTP/3. They set HSTS for a year.
The `HTTP://` version of the site redirects to `HTTPS://`.

Fastly manages the TLS certificates from Let's Encrypt for the servers they
run on the behalf of curl.

## Containers

The curl project offer container builds of curl. The source repository for
them is located at <https://github.com/curl/curl-container>.

Container images are hosted at <https://quay.io/repository/curl/curl> and
<https://hub.docker.com/r/curlimages/curl>

## DNS

The primary domain name, `curl.se` is managed by Kirei and is offered over
fault-tolerant anycast servers. High availability and fast access for
everyone.

The actual physical DNS files and origin bind instance is managed by Daniel
Stenberg.

## Mailing lists

The curl related mailing lists are hosted by Haxx AB on `lists.haxx.se` and
are maintained by Daniel Stenberg. This includes the mailman2 and Postfix
instances used for this.

## Email

We use a few rare additional curl related email aliases in the curl domains.
They go through the mail server `mail.haxx.se` maintained by Daniel Stenberg

## Bug-bounty

We run a [bug-bounty](https://curl.se/docs/bugbounty.html) on HackerOne. The
setup runs entirely at https://hackerone.com/curl.

The money part for the bug bounty is sponsored by the [Internet Bug
Bounty](https://hackerone.com/ibb).

## Open Collective

We use [Open Collective](https://opencollective.com/curl) as our "fiscal
host". All money sent to and received by the curl project is managed by Open
Collective.

## Merchandise

We have stickers, coffee mugs and coasters. They are managed by Daniel who
sits on the inventory. The best way to get your hands on curl merchandise is
to attend events where Daniel is physically.

## Chat

Some curl developers, maintainers, users and enthusiasts use IRC for real-time
chat about curl and related topics. This done in the `#curl` channel on the
`libra.chat` IRC network. **Daniel Stenberg** (`bagder`) is registered owner
of the channel. We do not run any IRC servers or services ourselves.

`curelbot` is a service in the channel that shows details about GitHub issues
and pull requests when publicly mentioned using #[number]. The bot is run by
user `TheAssassin`.

There is a Matrix bridge to the IRC channel called `matrix.curl.se`. The
bridge is setup and run by **Sergio Durigan Junior** and **Daniel Stenberg**.

[curl online chat documentation](https://curl.se/docs/irc.html)
