$! File: Build_GNV_curl_release_notes.com
$!
$! $Id$
$!
$! Build the release note file from the four components:
$!    1. The curl_release_note_start.txt
$!    2. The hp_ssl_release_info.txt
$!    3. [--]readme. file from the Curl distribution.
$!    4. The Curl_gnv-build_steps.txt.
$!
$! Set the name of the release notes from the GNV_PCSI_FILENAME_BASE
$! logical name.
$!
$! Copyright 2009, John Malmberg
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
$! 14-Jun-2009  J. Malmberg
$!
$!===========================================================================
$!
$ base_file = f$trnlnm("GNV_PCSI_FILENAME_BASE")
$ if base_file .eqs. ""
$ then
$   write sys$output "@MAKE_PCSI_CURL_KIT_NAME.COM has not been run."
$   goto all_exit
$ endif
$!
$!
$ curl_readme = f$search("sys$disk:[--]readme.")
$ if curl_readme .eqs. ""
$ then
$   curl_readme = f$search("sys$disk:[--]$README.")
$ endif
$ if curl_readme .eqs. ""
$ then
$    write sys$output "Can not find Curl readme file."
$    goto all_exit
$ endif
$!
$ curl_copying = f$search("sys$disk:[--]copying.")
$ if curl_copying .eqs. ""
$ then
$   curl_copying = f$search("sys$disk:[--]$COPYING.")
$ endif
$ if curl_copying .eqs. ""
$ then
$    write sys$output "Can not find Curl copying file."
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
$   write sys$output "Can not find VMS specific Curl readme file."
$   goto all_exit
$ endif
$!
$ if f$search("sys$disk:[]hp_ssl_release_info.txt") .eqs. ""
$ then
$   write sys$output "GNV_LINK_CURL.COM has not been run!"
$   goto all_exit
$ endif
$!
$ type/noheader 'curl_readme', 'vms_readme', -
                sys$disk:[]curl_release_note_start.txt, -
                sys$disk:[]hp_ssl_release_info.txt, -
                'curl_copying', -
                sys$disk:[]curl_gnv_build_steps.txt -
                /out='base_file'.release_notes
$!
$ purge 'base_file'.release_notes
$ rename 'base_file.release_notes ;1
$!
$all_exit:
$ exit
