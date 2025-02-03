$! File: Build_GNV_fetch_release_notes.com
$!
$! Build the release note file from the four components:
$!    1. The fetch_release_note_start.txt
$!    2. The hp_ssl_release_info.txt
$!    3. [--]readme. file from the Fetch distribution.
$!    4. The Fetch_gnv-build_steps.txt.
$!
$! Set the name of the release notes from the GNV_PCSI_FILENAME_BASE
$! logical name.
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
$!===========================================================================
$!
$ base_file = f$trnlnm("GNV_PCSI_FILENAME_BASE")
$ if base_file .eqs. ""
$ then
$   write sys$output "@MAKE_PCSI_FETCH_KIT_NAME.COM has not been run."
$   goto all_exit
$ endif
$!
$!
$ fetch_readme = f$search("sys$disk:[--]readme.")
$ if fetch_readme .eqs. ""
$ then
$   fetch_readme = f$search("sys$disk:[--]$README.")
$ endif
$ if fetch_readme .eqs. ""
$ then
$    write sys$output "Can not find Fetch readme file."
$    goto all_exit
$ endif
$!
$ fetch_copying = f$search("sys$disk:[--]copying.")
$ if fetch_copying .eqs. ""
$ then
$   fetch_copying = f$search("sys$disk:[--]$COPYING.")
$ endif
$ if fetch_copying .eqs. ""
$ then
$    write sys$output "Can not find Fetch copying file."
$    goto all_exit
$ endif
$!
$ vms_readme = f$search("sys$disk:[]readme.")
$ if vms_readme .eqs. ""
$ then
$   vms_readme = f$search("sys$disk:[]$README.")
$ endif
$ if vms_readme .eqs. ""
$ then
$   write sys$output "Can not find VMS specific Fetch readme file."
$   goto all_exit
$ endif
$!
$ fetch_release_notes = f$search("sys$disk:[--]release-notes.")
$ if fetch_release_notes .eqs. ""
$ then
$   fetch_release_notes = f$search("sys$disk:[--]$RELEASE-NOTES.")
$ endif
$ if fetch_release_notes .eqs. ""
$ then
$    write sys$output "Can not find Fetch release-notes file."
$    goto all_exit
$ endif
$!
$ if f$search("sys$disk:[]hp_ssl_release_info.txt") .eqs. ""
$ then
$   write sys$output "GNV_LINK_FETCH.COM has not been run!"
$   goto all_exit
$ endif
$!
$ type/noheader 'fetch_readme', 'vms_readme', -
                'fetch_release_notes', -
                sys$disk:[]fetch_release_note_start.txt, -
                sys$disk:[]hp_ssl_release_info.txt, -
                'fetch_copying', -
                sys$disk:[]fetch_gnv_build_steps.txt -
                /out='base_file'.release_notes
$!
$ purge 'base_file'.release_notes
$ rename 'base_file.release_notes ;1
$!
$all_exit:
$ exit
