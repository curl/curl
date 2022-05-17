$! File: PCSI_PRODUCT_GNV_CURL.COM
$!
$! $Id$
$!
$! This command file packages up the product CURL into a sequential
$! format kit
$!
$! Copyright 2013 - 2022, John Malmberg
$!
$! Permission to use, copy, modify, and/or distribute this software for any
$! purpose with or without fee is hereby granted, provided that the above
$! copyright notice and this permission notice appear in all copies.
$!
$! THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
$! WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
$! MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
$! ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
$! WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
$! ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
$! OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
$!
$! SPDX-License-Identifier: ISC
$!
$! 16-Jun-2009  J.Malmberg
$!
$!=========================================================================
$!
$! Save default
$ default_dir = f$environment("DEFAULT")
$!
$! Put things back on error.
$ on warning then goto all_exit
$!
$!
$ can_build = 1
$ producer = f$trnlnm("GNV_PCSI_PRODUCER")
$ if producer .eqs. ""
$ then
$   write sys$output "GNV_PCSI_PRODUCER logical name has not been set."
$   can_build = 0
$ endif
$ producer_full_name = f$trnlnm("GNV_PCSI_PRODUCER_FULL_NAME")
$ if producer_full_name .eqs. ""
$ then
$   write sys$output -
        "GNV_PCSI_PRODUCER_FULL_NAME logical name has not been set."
$   can_build = 0
$ endif
$ stage_root_name = f$trnlnm("STAGE_ROOT")
$ if stage_root_name .eqs. ""
$ then
$   write sys$output "STAGE_ROOT logical name has not been set."
$   can_build = 0
$ endif
$!
$ if (can_build .eq. 0)
$ then
$    write sys$output "Not able to build a kit."
$    goto all_exit
$ endif
$!
$! Make sure that the kit name is up to date for this build
$!----------------------------------------------------------
$ @MAKE_PCSI_CURL_KIT_NAME.COM
$!
$!
$! Make sure that the image is built
$!----------------------------------
$ arch_name = f$edit(f$getsyi("arch_name"),"UPCASE")
$ if f$search("[--.src]curl.exe") .eqs. ""
$ then
$   build_it = 1
$   libfile = "[.packages.vms.''arch_name']curllib.olb"
$   if f$search(libfile) .nes. ""
$   then
$       build_it = 0
$   else
$       ! GNV based build
$       libfile = "[.lib.^.libs]libcurl.a"
$       if f$search(libfile) .nes. ""
$       then
$           build_it = 0;
$       endif
$   endif
$   if build_it .eq. 1
$   then
$       @build_vms list
$   endif
$   @gnv_link_curl.com
$ endif
$!
$! Make sure that the release note file name is up to date
$!---------------------------------------------------------
$ @BUILD_GNV_CURL_RELEASE_NOTES.COM
$!
$!
$! Make sure that the source has been backed up.
$!----------------------------------------------
$ arch_type = f$getsyi("ARCH_NAME")
$ arch_code = f$extract(0, 1, arch_type)
$ @backup_gnv_curl_src.com
$!
$! Regenerate the PCSI description file.
$!--------------------------------------
$ @BUILD_GNV_CURL_PCSI_DESC.COM
$!
$! Regenerate the PCSI Text file.
$!---------------------------------
$ @BUILD_GNV_CURL_PCSI_TEXT.COM
$!
$!
$! Parse the kit name into components.
$!---------------------------------------
$ kit_name = f$trnlnm("GNV_PCSI_KITNAME")
$ if kit_name .eqs. ""
$ then
$   write sys$output "@MAKE_PCSI_CURL_KIT_NAME.COM has not been run."
$   goto all_exit
$ endif
$ producer = f$element(0, "-", kit_name)
$ base = f$element(1, "-", kit_name)
$ product_name = f$element(2, "-", kit_name)
$ mmversion = f$element(3, "-", kit_name)
$ majorver = f$extract(0, 3, mmversion)
$ minorver = f$extract(3, 2, mmversion)
$ updatepatch = f$element(4, "-", kit_name)
$ if updatepatch .eqs. "" then updatepatch = ""
$!
$ version_fao = "!AS.!AS"
$ mmversion = f$fao(version_fao, "''majorver'", "''minorver'")
$ if updatepatch .nes. ""
$ then
$   version = "''mmversion'" + "-" + updatepatch
$ else
$   version = "''mmversion'"
$ endif
$!
$ @stage_curl_install remove
$ @stage_curl_install
$!
$! Move to the base directories
$ set def [--]
$ current_default = f$environment("DEFAULT")
$ my_dir = f$parse(current_default,,,"DIRECTORY") - "[" - "<" - ">" - "]"
$!
$!
$!
$ source = "''default_dir'"
$ src1 = "new_gnu:[usr.bin],"
$ src2 = "new_gnu:[usr.include.curl],"
$ src3 = "new_gnu:[usr.lib],"
$ src4 = "new_gnu:[usr.lib.pkgconfig],"
$ src5 = "new_gnu:[usr.share.man.man1],"
$ src6 = "new_gnu:[usr.share.man.man3],"
$ src7 = "new_gnu:[vms_src],"
$ src8 = "new_gnu:[common_src],"
$ src9 = "prj_root:[''my_dir'],prj_root:[''my_dir'.src]"
$ gnu_src = src1 + src2 + src3 + src4 + src5 + src6 + src7 + src8 + src9
$!
$!
$ base = ""
$ if arch_name .eqs. "ALPHA" then base = "AXPVMS"
$ if arch_name .eqs. "IA64" then base = "I64VMS"
$ if arch_name .eqs. "VAX" then base = "VAXVMS"
$!
$ if base .eqs. "" then exit 44
$!
$ pcsi_option = "/option=noconfirm"
$ if arch_code .eqs. "V"
$ then
$   pcsi_option = ""
$ endif
$!
$!
$product package 'product_name' -
 /base='base' -
 /producer='producer' -
 /source='source' -
 /destination=STAGE_ROOT:[KIT] -
 /material=('gnu_src','source') -
 /format=sequential 'pcsi_option'
$!
$!
$! VAX can not do a compressed kit.
$! ZIP -9 "-V" does a better job, so no reason to normally build a compressed
$! kit.
$!----------------------------------
$if p1 .eqs. "COMPRESSED"
$then
$   if arch_code .nes. "V"
$   then
$       product copy /options=(novalidate, noconfirm) /format=compressed -
        'product_name' -
        /source=stage_root:[kit]/dest=stage_root:[kit] -
        /version='version'/base='base'
$   endif
$endif
$!
$all_exit:
$ set def 'default_dir'
$ exit
