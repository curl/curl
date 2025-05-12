<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# curl distros

<!-- markdown-link-check-disable -->

Lots of organizations distribute curl packages to end users. This is a
collection of pointers to where to learn more about curl on and with each
distro. Those marked *Rolling Release* typically run the latest version of curl
and are therefore less likely to have back-ported patches to older versions.

We discuss curl distro issues, patches and collaboration on the [curl-distros
mailing list](https://lists.haxx.se/listinfo/curl-distros) ([list
archives](https://curl.se/mail/list.cgi?list=curl-distros)).

## AlmaLinux

- curl package source and patches: https://git.almalinux.org/rpms/curl/
- curl issues: https://bugs.almalinux.org/view_all_bug_page.php click Category and choose curl
- curl security: https://errata.almalinux.org/ search for curl

## Alpine Linux

- curl: https://pkgs.alpinelinux.org/package/edge/main/x86_64/curl
- curl issues: https://gitlab.alpinelinux.org/alpine/aports/-/issues
- curl security: https://security.alpinelinux.org/srcpkg/curl
- curl package source and patches: https://gitlab.alpinelinux.org/alpine/aports/-/tree/master/main/curl

## Alt Linux

- curl: https://packages.altlinux.org/en/search/?q=curl
- curl issues: https://packages.altlinux.org/en/sisyphus/srpms/curl/issues/
- curl patches: https://git.altlinux.org/gears/c/curl.git?p=curl.git;a=tree;f=.gear

## Arch Linux

*Rolling Release*

- curl: https://archlinux.org/packages/core/x86_64/curl/
- curl issues: https://gitlab.archlinux.org/archlinux/packaging/packages/curl/-/issues
- curl security: https://security.archlinux.org/package/curl
- curl wiki: https://wiki.archlinux.org/title/CURL

## Buildroot

*Rolling Release*

- curl package source and patches: https://git.buildroot.net/buildroot/tree/package/libcurl
- curl issues: https://bugs.buildroot.org/buglist.cgi?quicksearch=curl

## Chimera

- curl package source and patches: https://github.com/chimera-linux/cports/tree/master/main/curl

## Clear Linux

*Rolling Release*

- curl: https://github.com/clearlinux-pkgs/curl
- curl issues: https://github.com/clearlinux/distribution/issues

## Conary

- curl: https://github.com/conan-io/conan-center-index/tree/master/recipes/libcurl
- curl issues: https://github.com/conan-io/conan-center-index/issues
- curl patches: https://github.com/conan-io/conan-center-index/tree/master/recipes/libcurl (in `all/patches/*`, if any)

## conda-forge

- curl: https://github.com/conda-forge/curl-feedstock
- curl issues: https://github.com/conda-forge/curl-feedstock/issues

## CRUX

- curl: https://crux.nu/portdb/?a=search&q=curl
- curl issues: https://git.crux.nu/ports/core/issues/?type=all&state=open&q=curl

## curl-for-win

(this is the official curl binaries for Windows shipped by the curl project)

*Rolling Release*

- curl: https://curl.se/windows/
- curl patches: https://github.com/curl/curl-for-win/blob/main/curl.patch (if any)
- build-specific issues: https://github.com/curl/curl-for-win/issues

Issues and patches for this are managed in the main curl project.

## Cygwin

- curl: https://cygwin.com/cgit/cygwin-packages/curl/tree/curl.cygport
- curl patches: https://cygwin.com/cgit/cygwin-packages/curl/tree
- curl issues: https://inbox.sourceware.org/cygwin/?q=s%3Acurl

## Cygwin (cross mingw64)

- mingw64-x86_64-curl: https://cygwin.com/cgit/cygwin-packages/mingw64-x86_64-curl/tree/mingw64-x86_64-curl.cygport
- mingw64-x86_64-curl patches: https://cygwin.com/cgit/cygwin-packages/mingw64-x86_64-curl/tree
- mingw64-x86_64-curl issues: https://inbox.sourceware.org/cygwin/?q=s%3Amingw64-x86_64-curl

## Debian

- curl: https://tracker.debian.org/pkg/curl
- curl issues: https://bugs.debian.org/cgi-bin/pkgreport.cgi?pkg=curl
- curl patches: https://udd.debian.org/patches.cgi?src=curl
- curl patches: https://salsa.debian.org/debian/curl (in debian/* branches, inside the folder debian/patches)

## Fedora

- curl: https://src.fedoraproject.org/rpms/curl
- curl issues: [bugzilla](https://bugzilla.redhat.com/buglist.cgi?bug_status=NEW&bug_status=ASSIGNED&classification=Fedora&product=Fedora&product=Fedora%20EPEL&component=curl)
- curl patches: [list of patches in package git](https://src.fedoraproject.org/rpms/curl/tree/rawhide)

## FreeBSD

- curl: https://cgit.freebsd.org/ports/tree/ftp/curl
- curl patches: https://cgit.freebsd.org/ports/tree/ftp/curl
- curl issues: https://bugs.freebsd.org/bugzilla/buglist.cgi?bug_status=__open__&order=Importance&product=Ports%20%26%20Packages&query_format=advanced&short_desc=curl&short_desc_type=allwordssubstr

## Gentoo Linux

*Rolling Release*

- curl: https://packages.gentoo.org/packages/net-misc/curl
- curl issues: https://bugs.gentoo.org/buglist.cgi?quicksearch=net-misc/curl
- curl package sources and patches: https://gitweb.gentoo.org/repo/gentoo.git/tree/net-misc/curl/

## GNU Guix

*Rolling Release*

- curl: https://git.savannah.gnu.org/gitweb/?p=guix.git;a=blob;f=gnu/packages/curl.scm;hb=HEAD
- curl issues: https://issues.guix.gnu.org/search?query=curl

## Homebrew

*Rolling Release*

- curl: https://formulae.brew.sh/formula/curl

Homebrew's policy is that all patches and issues should be submitted upstream
unless it is specific to Homebrew's way of packaging software.

## MacPorts

*Rolling Release*

- curl: https://github.com/macports/macports-ports/tree/master/net/curl
- curl issues: https://trac.macports.org/query?0_port=curl&0_port_mode=%7E&0_status=%21closed
- curl patches: https://github.com/macports/macports-ports/tree/master/net/curl/files

## Mageia

- curl: https://svnweb.mageia.org/packages/cauldron/curl/current/SPECS/curl.spec?view=markup
- curl issues: https://bugs.mageia.org/buglist.cgi?bug_status=NEW&bug_status=UNCONFIRMED&bug_status=NEEDINFO&bug_status=UPSTREAM&bug_status=ASSIGNED&component=RPM%20Packages&f1=cf_rpmpkg&list_id=176576&o1=casesubstring&product=Mageia&query_format=advanced&v1=curl
- curl patches: https://svnweb.mageia.org/packages/cauldron/curl/current/SOURCES/
- curl patches in stable distro releases: https://svnweb.mageia.org/packages/updates/<STABLE_VERSION>/curl/current/SOURCES/
- curl security: https://advisories.mageia.org/src_curl.html

## MSYS2

*Rolling Release*

- curl: https://github.com/msys2/MSYS2-packages/tree/master/curl
- curl issues: https://github.com/msys2/MSYS2-packages/issues
- curl patches: https://github.com/msys2/MSYS2-packages/tree/master/curl (`*.patch`)

## MSYS2 (mingw-w64)

*Rolling Release*

- curl: https://github.com/msys2/MINGW-packages/tree/master/mingw-w64-curl
- curl issues: https://github.com/msys2/MINGW-packages/issues
- curl patches: https://github.com/msys2/MINGW-packages/tree/master/mingw-w64-curl (`*.patch`)

## Muldersoft

*Rolling Release*

- curl: https://github.com/lordmulder/cURL-build-win32
- curl issues: https://github.com/lordmulder/cURL-build-win32/issues
- curl patches: https://github.com/lordmulder/cURL-build-win32/tree/master/patch

## NixOS

- curl: https://github.com/NixOS/nixpkgs/blob/master/pkgs/tools/networking/curl/default.nix
  (TODO: page has moved)
- curl issues: https://github.com/NixOS/nixpkgs

nixpkgs is the package repository used by the NixOS Linux distribution, but
can also be used on other distributions

## OmniOS

- curl: https://github.com/omniosorg/omnios-build/tree/master/build/curl
- curl issues: https://github.com/omniosorg/omnios-build/issues
- curl patches: https://github.com/omniosorg/omnios-build/tree/master/build/curl/patches

## OpenIndiana

- curl: https://github.com/OpenIndiana/oi-userland/tree/oi/hipster/components/web/curl
- curl issues: https://www.illumos.org/projects/openindiana/issues
- curl patches: https://github.com/OpenIndiana/oi-userland/tree/oi/hipster/components/web/curl/patches

## OpenSUSE

- curl source and patches: https://build.opensuse.org/package/show/openSUSE%3AFactory/curl

## Oracle Solaris

- curl: https://github.com/oracle/solaris-userland/tree/master/components/curl
- curl issues: https://support.oracle.com/ (requires support contract)
- curl patches: https://github.com/oracle/solaris-userland/tree/master/components/curl/patches

## OpenEmbedded / Yocto Project

*Rolling Release*

- curl: https://layers.openembedded.org/layerindex/recipe/5765/
- curl issues: https://bugzilla.yoctoproject.org/
- curl patches: https://git.openembedded.org/openembedded-core/tree/meta/recipes-support/curl

## PLD Linux

- curl package source and patches: https://github.com/pld-linux/curl
- curl issues: https://bugs.launchpad.net/pld-linux?field.searchtext=curl&search=Search&field.status%3Alist=NEW&field.status%3Alist=INCOMPLETE_WITH_RESPONSE&field.status%3Alist=INCOMPLETE_WITHOUT_RESPONSE&field.status%3Alist=CONFIRMED&field.status%3Alist=TRIAGED&field.status%3Alist=INPROGRESS&field.status%3Alist=FIXCOMMITTED&field.assignee=&field.bug_reporter=&field.omit_dupes=on&field.has_patch=&field.has_no_package=

## pkgsrc

- curl: https://github.com/NetBSD/pkgsrc/tree/trunk/www/curl
- curl issues: https://github.com/NetBSD/pkgsrc/issues
- curl patches: https://github.com/NetBSD/pkgsrc/tree/trunk/www/curl/patches

## Red Hat Enterprise Linux / CentOS Stream

- curl: https://kojihub.stream.centos.org/koji/packageinfo?packageID=217
- curl issues: https://issues.redhat.com/secure/CreateIssueDetails!init.jspa?pid=12332745&issuetype=1&components=12377466&priority=10300
- curl patches: https://gitlab.com/redhat/centos-stream/rpms/curl

## Rocky Linux

- curl: https://git.rockylinux.org/staging/rpms/curl/-/blob/r9/SPECS/curl.spec
- curl issues: https://bugs.rockylinux.org
- curl patches: https://git.rockylinux.org/staging/rpms/curl/-/tree/r9/SOURCES

## SerenityOS

- curl: https://github.com/SerenityOS/serenity/tree/master/Ports/curl
- curl issues: https://github.com/SerenityOS/serenity/issues?q=label%3Aports
- curl patches: https://github.com/SerenityOS/serenity/tree/master/Ports/curl/patches

## SmartOS

- curl: https://github.com/TritonDataCenter/illumos-extra/tree/master/curl
- curl issues: https://github.com/TritonDataCenter/illumos-extra/issues
- curl patches: https://github.com/TritonDataCenter/illumos-extra/tree/master/curl/Patches

## SPACK

- curl package source and patches: https://github.com/spack/spack/tree/develop/var/spack/repos/builtin/packages/curl

## vcpkg

*Rolling Release*

- curl: https://github.com/microsoft/vcpkg/tree/master/ports/curl
- curl issues: https://github.com/microsoft/vcpkg/issues
- curl patches: https://github.com/microsoft/vcpkg/tree/master/ports/curl (`*.patch`)

## Void Linux

*Rolling Release*

- curl: https://github.com/void-linux/void-packages/tree/master/srcpkgs/curl
- curl issues: https://github.com/void-linux/void-packages/issues
- curl patches: https://github.com/void-linux/void-packages/tree/master/srcpkgs/curl/patches

## Wolfi

*Rolling Release*

- curl: https://github.com/wolfi-dev/os/blob/main/curl.yaml
