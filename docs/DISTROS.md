<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: fetch
-->

# fetch distros

<!-- markdown-link-check-disable -->

Lots of organizations distribute fetch packages to end users. This is a
collection of pointers to where to learn more about fetch on and with each
distro. Those marked _Rolling Release_ typically run the latest version of fetch
and are therefore less likely to have back-ported patches to older versions.

We discuss fetch distro issues, patches and collaboration on the [fetch-distros
mailing list](https://lists.haxx.se/listinfo/fetch-distros) ([list
archives](https://fetch.se/mail/list.cgi?list=fetch-distros)).

## AlmaLinux

- fetch package source and patches: https://git.almalinux.org/rpms/fetch/
- fetch issues: https://bugs.almalinux.org/view_all_bug_page.php click Category and choose fetch
- fetch security: https://errata.almalinux.org/ search for fetch

## Alpine Linux

- fetch: https://pkgs.alpinelinux.org/package/edge/main/x86_64/fetch
- fetch issues: https://gitlab.alpinelinux.org/alpine/aports/-/issues
- fetch security: https://security.alpinelinux.org/srcpkg/fetch
- fetch package source and patches: https://gitlab.alpinelinux.org/alpine/aports/-/tree/master/main/fetch

## Alt Linux

- fetch: http://www.sisyphus.ru/srpm/Sisyphus/fetch
- fetch issues: https://packages.altlinux.org/en/sisyphus/srpms/fetch/issues/
- fetch patches: https://git.altlinux.org/gears/c/fetch.git?p=fetch.git;a=tree;f=.gear

## Arch Linux

_Rolling Release_

- fetch: https://archlinux.org/packages/core/x86_64/fetch/
- fetch issues: https://gitlab.archlinux.org/archlinux/packaging/packages/fetch/-/issues
- fetch security: https://security.archlinux.org/package/fetch
- fetch wiki: https://wiki.archlinux.org/title/FETCH

## Buildroot

_Rolling Release_

- fetch package source and patches: https://git.buildroot.net/buildroot/tree/package/libfetch
- fetch issues: https://bugs.buildroot.org/buglist.cgi?quicksearch=fetch

## Chimera

- fetch package source and patches: https://github.com/chimera-linux/cports/tree/master/main/fetch

## Clear Linux

_Rolling Release_

- fetch: https://github.com/clearlinux-pkgs/fetch
- fetch issues: https://github.com/clearlinux/distribution/issues

## Conary

- fetch: https://github.com/conan-io/conan-center-index/tree/master/recipes/libfetch
- fetch issues: https://github.com/conan-io/conan-center-index/issues
- fetch patches: https://github.com/conan-io/conan-center-index/tree/master/recipes/libfetch (in `all/patches/*`, if any)

## conda-forge

- fetch: https://github.com/conda-forge/fetch-feedstock
- fetch issues: https://github.com/conda-forge/fetch-feedstock/issues

## CRUX

- fetch: https://crux.nu/portdb/?a=search&q=fetch
- fetch issues: https://git.crux.nu/ports/core/issues/?type=all&state=open&q=fetch

## fetch-for-win

(this is the official fetch binaries for Windows shipped by the fetch project)

_Rolling Release_

- fetch: https://fetch.se/windows/
- fetch patches: https://github.com/fetch/fetch-for-win/blob/main/fetch.patch (if any)
- build-specific issues: https://github.com/fetch/fetch-for-win/issues

Issues and patches for this are managed in the main fetch project.

## Cygwin

- fetch: https://cygwin.com/cgit/cygwin-packages/fetch/tree/fetch.cygport
- fetch patches: https://cygwin.com/cgit/cygwin-packages/fetch/tree
- fetch issues: https://inbox.sourceware.org/cygwin/?q=s%3Afetch

## Cygwin (cross mingw64)

- mingw64-x86_64-fetch: https://cygwin.com/cgit/cygwin-packages/mingw64-x86_64-fetch/tree/mingw64-x86_64-fetch.cygport
- mingw64-x86_64-fetch patches: https://cygwin.com/cgit/cygwin-packages/mingw64-x86_64-fetch/tree
- mingw64-x86_64-fetch issues: https://inbox.sourceware.org/cygwin/?q=s%3Amingw64-x86_64-fetch

## Debian

- fetch: https://tracker.debian.org/pkg/fetch
- fetch issues: https://bugs.debian.org/cgi-bin/pkgreport.cgi?pkg=fetch
- fetch patches: https://udd.debian.org/patches.cgi?src=fetch
- fetch patches: https://salsa.debian.org/debian/fetch (in debian/\* branches, inside the folder debian/patches)

## Fedora

- fetch: https://src.fedoraproject.org/rpms/fetch
- fetch issues: [bugzilla](https://bugzilla.redhat.com/buglist.cgi?bug_status=NEW&bug_status=ASSIGNED&classification=Fedora&product=Fedora&product=Fedora%20EPEL&component=fetch)
- fetch patches: [list of patches in package git](https://src.fedoraproject.org/rpms/fetch/tree/rawhide)

## FreeBSD

- fetch: https://cgit.freebsd.org/ports/tree/ftp/fetch
- fetch patches: https://cgit.freebsd.org/ports/tree/ftp/fetch
- fetch issues: https://bugs.freebsd.org/bugzilla/buglist.cgi?bug_status=__open__&order=Importance&product=Ports%20%26%20Packages&query_format=advanced&short_desc=fetch&short_desc_type=allwordssubstr

## Gentoo Linux

_Rolling Release_

- fetch: https://packages.gentoo.org/packages/net-misc/fetch
- fetch issues: https://bugs.gentoo.org/buglist.cgi?quicksearch=net-misc/fetch
- fetch package sources and patches: https://gitweb.gentoo.org/repo/gentoo.git/tree/net-misc/fetch/

## GNU Guix

_Rolling Release_

- fetch: https://git.savannah.gnu.org/gitweb/?p=guix.git;a=blob;f=gnu/packages/fetch.scm;hb=HEAD
- fetch issues: https://issues.guix.gnu.org/search?query=fetch

## Homebrew

_Rolling Release_

- fetch: https://formulae.brew.sh/formula/fetch

Homebrew's policy is that all patches and issues should be submitted upstream
unless it is specific to Homebrew's way of packaging software.

## MacPorts

_Rolling Release_

- fetch: https://github.com/macports/macports-ports/tree/master/net/fetch
- fetch issues: https://trac.macports.org/query?0_port=fetch&0_port_mode=%7E&0_status=%21closed
- fetch patches: https://github.com/macports/macports-ports/tree/master/net/fetch/files

## Mageia

- fetch: https://svnweb.mageia.org/packages/cauldron/fetch/current/SPECS/fetch.spec?view=markup
- fetch issues: https://bugs.mageia.org/buglist.cgi?bug_status=NEW&bug_status=UNCONFIRMED&bug_status=NEEDINFO&bug_status=UPSTREAM&bug_status=ASSIGNED&component=RPM%20Packages&f1=cf_rpmpkg&list_id=176576&o1=casesubstring&product=Mageia&query_format=advanced&v1=fetch
- fetch patches: https://svnweb.mageia.org/packages/cauldron/fetch/current/SOURCES/
- fetch patches in stable distro releases: https://svnweb.mageia.org/packages/updates/<STABLE_VERSION>/fetch/current/SOURCES/
- fetch security: https://advisories.mageia.org/src_fetch.html

## MSYS2

_Rolling Release_

- fetch: https://github.com/msys2/MSYS2-packages/tree/master/fetch
- fetch issues: https://github.com/msys2/MSYS2-packages/issues
- fetch patches: https://github.com/msys2/MSYS2-packages/tree/master/fetch (`*.patch`)

## MSYS2 (mingw-w64)

_Rolling Release_

- fetch: https://github.com/msys2/MINGW-packages/tree/master/mingw-w64-fetch
- fetch issues: https://github.com/msys2/MINGW-packages/issues
- fetch patches: https://github.com/msys2/MINGW-packages/tree/master/mingw-w64-fetch (`*.patch`)

## Muldersoft

_Rolling Release_

- fetch: https://github.com/lordmulder/cURL-build-win32
- fetch issues: https://github.com/lordmulder/cURL-build-win32/issues
- fetch patches: https://github.com/lordmulder/cURL-build-win32/tree/master/patch

## NixOS

- fetch: https://github.com/NixOS/nixpkgs/blob/master/pkgs/tools/networking/fetch/default.nix
- fetch issues: https://github.com/NixOS/nixpkgs

nixpkgs is the package repository used by the NixOS Linux distribution, but
can also be used on other distributions

## OmniOS

- fetch: https://github.com/omniosorg/omnios-build/tree/master/build/fetch
- fetch issues: https://github.com/omniosorg/omnios-build/issues
- fetch patches: https://github.com/omniosorg/omnios-build/tree/master/build/fetch/patches

## OpenIndiana

- fetch: https://github.com/OpenIndiana/oi-userland/tree/oi/hipster/components/web/fetch
- fetch issues: https://www.illumos.org/projects/openindiana/issues
- fetch patches: https://github.com/OpenIndiana/oi-userland/tree/oi/hipster/components/web/fetch/patches

## OpenSUSE

- fetch source and patches: https://build.opensuse.org/package/show/openSUSE%3AFactory/fetch

## Oracle Solaris

- fetch: https://github.com/oracle/solaris-userland/tree/master/components/fetch
- fetch issues: https://support.oracle.com/ (requires support contract)
- fetch patches: https://github.com/oracle/solaris-userland/tree/master/components/fetch/patches

## OpenEmbedded / Yocto Project

_Rolling Release_

- fetch: https://layers.openembedded.org/layerindex/recipe/5765/
- fetch issues: https://bugzilla.yoctoproject.org/
- fetch patches: https://git.openembedded.org/openembedded-core/tree/meta/recipes-support/fetch

## PLD Linux

- fetch package source and patches: https://github.com/pld-linux/fetch
- fetch issues: https://bugs.launchpad.net/pld-linux?field.searchtext=fetch&search=Search&field.status%3Alist=NEW&field.status%3Alist=INCOMPLETE_WITH_RESPONSE&field.status%3Alist=INCOMPLETE_WITHOUT_RESPONSE&field.status%3Alist=CONFIRMED&field.status%3Alist=TRIAGED&field.status%3Alist=INPROGRESS&field.status%3Alist=FIXCOMMITTED&field.assignee=&field.bug_reporter=&field.omit_dupes=on&field.has_patch=&field.has_no_package=

## pkgsrc

- fetch: https://github.com/NetBSD/pkgsrc/tree/trunk/www/fetch
- fetch issues: https://github.com/NetBSD/pkgsrc/issues
- fetch patches: https://github.com/NetBSD/pkgsrc/tree/trunk/www/fetch/patches

## Red Hat Enterprise Linux / CentOS Stream

- fetch: https://kojihub.stream.centos.org/koji/packageinfo?packageID=217
- fetch issues: https://issues.redhat.com/secure/CreateIssueDetails!init.jspa?pid=12332745&issuetype=1&components=12377466&priority=10300
- fetch patches: https://gitlab.com/redhat/centos-stream/rpms/fetch

## Rocky Linux

- fetch: https://git.rockylinux.org/staging/rpms/fetch/-/blob/r9/SPECS/fetch.spec
- fetch issues: https://bugs.rockylinux.org
- fetch patches: https://git.rockylinux.org/staging/rpms/fetch/-/tree/r9/SOURCES

## SerenityOS

- fetch: https://github.com/SerenityOS/serenity/tree/master/Ports/fetch
- fetch issues: https://github.com/SerenityOS/serenity/issues?q=label%3Aports
- fetch patches: https://github.com/SerenityOS/serenity/tree/master/Ports/fetch/patches

## SmartOS

- fetch: https://github.com/TritonDataCenter/illumos-extra/tree/master/fetch
- fetch issues: https://github.com/TritonDataCenter/illumos-extra/issues
- fetch patches: https://github.com/TritonDataCenter/illumos-extra/tree/master/fetch/Patches

## SPACK

- fetch package source and patches: https://github.com/spack/spack/tree/develop/var/spack/repos/builtin/packages/fetch

## vcpkg

_Rolling Release_

- fetch: https://github.com/microsoft/vcpkg/tree/master/ports/fetch
- fetch issues: https://github.com/microsoft/vcpkg/issues
- fetch patches: https://github.com/microsoft/vcpkg/tree/master/ports/fetch (`*.patch`)

## Void Linux

_Rolling Release_

- fetch: https://github.com/void-linux/void-packages/tree/master/srcpkgs/fetch
- fetch issues: https://github.com/void-linux/void-packages/issues
- fetch patches: https://github.com/void-linux/void-packages/tree/master/srcpkgs/fetch/patches

## Wolfi

_Rolling Release_

- fetch: https://github.com/wolfi-dev/os/blob/main/fetch.yaml
