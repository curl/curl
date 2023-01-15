$! File: MAKE_PCSI_CURL_KIT_NAME.COM
$!
$! Calculates the PCSI kit name for use in building an installation kit.
$! PCSI is HP's PolyCenter Software Installation Utility.
$!
$! The results are stored in as logical names so that other procedures
$! can use them.
$!
$! Copyright (C) John Malmberg
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
$!========================================================================
$!
$! Save default
$ default_dir = f$environment("DEFAULT")
$!
$! Move to the base directories
$ set def [--]
$!
$! Put things back on error.
$ on warning then goto all_exit
$!
$! The producer is the name or common abbreviation for the entity that is
$! making the kit.  It must be set as a logical name before running this
$! procedure.
$!
$! HP documents the producer as the legal owner of the software, but for
$! open source work, it should document who is creating the package for
$! distribution.
$!
$ producer = f$trnlnm("GNV_PCSI_PRODUCER")
$ if producer .eqs. ""
$ then
$   write sys$output "The logical name GNV_PCSI_PRODUCER needs to be defined."
$   write sys$output "This should be set to the common abbreviation or name of"
$   write sys$output "the entity creating this kit.  If you are an individual"
$   write sys$output "then use your initials."
$   goto all_exit
$ endif
$ producer_full_name = f$trnlnm("GNV_PCSI_PRODUCER_FULL_NAME")
$ if producer_full_name .eqs. ""
$ then
$   write sys$output "The logical name GNV_PCSI_PRODUCER_FULL_NAME needs to"
$   write sys$output "be defined.  This should be set to the full name of"
$   write sys$output "the entity creating this kit.  If you are an individual"
$   write sys$output "then use your name."
$   write sys$output "EX: DEFINE GNV_PCSI_PRODUCER_FULL_NAME ""First M. Last"""
$   goto all_exit
$ endif
$!
$ write sys$output "*****"
$ write sys$output "***** Producer = ''producer'"
$ write sys$output "*****"
$!
$!
$! Base is one of 'VMS', 'AXPVMS', 'I64VMS', 'VAXVMS' and indicates what
$! binaries are in the kit.  A kit with just 'VMS' can be installed on all
$! architectures.
$!
$ base = "VMS"
$ arch_type = f$getsyi("ARCH_NAME")
$ code = f$extract(0, 1, arch_type)
$ if (code .eqs. "I") then base = "I64VMS"
$ if (code .eqs. "V") then base = "VAXVMS"
$ if (code .eqs. "A") then base = "AXPVMS"
$!
$!
$ product = "curl"
$!
$!
$! We need to get the version from curlver_h.  It will have a line like
$! #define LIBCURL_VERSION "7.31.0"
$!   or
$! #define LIBCURL_VERSION "7.32.0-20130731".
$!
$! The dash indicates that this is a daily pre-release.
$!
$!
$ open/read/error=version_loop_end vhf [.include.curl]curlver.h
$ version_loop:
$   read vhf line_in
$   if line_in .eqs. "" then goto version_loop
$   if f$locate("#define LIBCURL_VERSION ", line_in) .ne. 0
$   then
$       goto version_loop
$   endif
$   raw_version = f$element(2," ", line_in) - """" - """"
$ version_loop_end:
$ close vhf
$!
$!
$ eco_level = ""
$ if f$search("''default_dir'vms_eco_level.h") .nes. ""
$ then
$   open/read ef 'default_dir'vms_eco_level.h
$ecolevel_loop:
$       read/end=ecolevel_loop_end ef line_in
$       prefix = f$element(0, " ", line_in)
$       if prefix .nes. "#define" then goto ecolevel_loop
$       key = f$element(1, " ", line_in)
$       value = f$element(2, " ", line_in) - """" - """"
$       if key .eqs. "VMS_ECO_LEVEL"
$       then
$           eco_level = "''value'"
$           if eco_level .eqs. "0"
$           then
$               eco_level = ""
$           else
$               eco_level = "E" + eco_level
$           endif
$           goto ecolevel_loop_end
$       endif
$       goto ecolevel_loop
$ecolevel_loop_end:
$   close ef
$ endif
$!
$!
$! This translates to V0732-0 or D0732-0
$! We encode the snapshot date into the version as an ECO since a daily
$! can never have an ECO.
$!
$! version_type = 'V' for a production release, and 'D' for a build from a
$! daiy snapshot of the curl source.
$ majorver = f$element(0, ".", raw_version)
$ minorver = f$element(1, ".", raw_version)
$ raw_update = f$element(2, ".", raw_version)
$ update = f$element(0, "-", raw_update)
$ if update .eqs. "0" then update = ""
$ daily_tag = f$element(1, "-", raw_update)
$ vtype = "V"
$ patch = ""
$ if daily_tag .nes. "-"
$ then
$   vtype = "D"
$   daily_tag_len = f$length(daily_tag)
$   daily_tag = f$extract(4, daily_tag_len - 4, daily_tag)
$   patch = vtype + daily_tag
$   product = product + "_d"
$ else
$   daily_tag = ""
$   if eco_level .nes. "" then patch = eco_level
$ endif
$!
$!
$ version_fao = "!2ZB!2ZB"
$ mmversion = f$fao(version_fao, 'majorver', 'minorver')
$ version = vtype + "''mmversion'"
$ if update .nes. "" .or. patch .nes. ""
$ then
$!  The presence of a patch implies an update
$   if update .eqs. "" .and. patch .nes. "" then update = "0"
$   version = version + "-" + update + patch
$   fversion = version
$ else
$   fversion = version
$   version = version + "-"
$ endif
$!
$! Kit type 1 is complete kit, the only type that this procedure will make.
$ kittype = 1
$!
$! Write out a logical name for the resulting base kit name.
$ name = "''producer'-''base'-''product'-''version'-''kittype'"
$ define GNV_PCSI_KITNAME "''name'"
$ fname = "''product'-''fversion'"
$ define GNV_PCSI_FILENAME_BASE "''fname'"
$ write sys$output "*****"
$ write sys$output "***** GNV_PCSI_KITNAME = ''name'."
$ write sys$output "***** GNV_PCSI_FILENAME_BASE = ''fname'."
$ write sys$output "*****"
$!
$all_exit:
$ set def 'default_dir'
$ exit '$status'
