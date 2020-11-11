$! File: Build_GNV_curl_pcsi_text.com
$!
$! $Id$
$!
$! Build the *.pcsi$text file from the four components:
$!    1. Generated =product header section
$!    2. [--]readme. file from the Curl distribution, modified to fit
$!       a pcsi$text file format.
$!    3. [--]copying file from the Curl distribution, modified to fit
$!       a pcsi$text file format.
$!    4. Generated Producer section.
$!
$! Set the name of the release notes from the GNV_PCSI_FILENAME_BASE
$!
$! Copyright 2009 - 2020, John Malmberg
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
$!
$! 15-Jun-2009  J. Malmberg
$!
$!===========================================================================
$!
$ kit_name = f$trnlnm("GNV_PCSI_KITNAME")
$ if kit_name .eqs. ""
$ then
$   write sys$output "@MAKE_PCSI_CURL_KIT_NAME.COM has not been run."
$   goto all_exit
$ endif
$ producer = f$trnlnm("GNV_PCSI_PRODUCER")
$ if producer .eqs. ""
$ then
$   write sys$output "@MAKE_PCSI_CURL_KIT_NAME.COM has not been run."
$   goto all_exit
$ endif
$ producer_full_name = f$trnlnm("GNV_PCSI_PRODUCER_FULL_NAME")
$ if producer_full_name .eqs. ""
$ then
$   write sys$output "@MAKE_PCSI_CURL_KIT_NAME.COM has not been run."
$   goto all_exit
$ endif
$!
$!
$! Parse the kit name into components.
$!---------------------------------------
$ producer = f$element(0, "-", kit_name)
$ base = f$element(1, "-", kit_name)
$ product = f$element(2, "-", kit_name)
$ mmversion = f$element(3, "-", kit_name)
$ majorver = f$extract(0, 3, mmversion)
$ minorver = f$extract(3, 2, mmversion)
$ updatepatch = f$element(4, "-", kit_name)
$ if updatepatch .eqs. "-" then updatepatch = ""
$!
$!
$ product_line = "=product ''producer' ''base' ''product'"
$ if updatepatch .eqs. ""
$ then
$     product_name = " ''majorver'.''minorver'"
$ else
$     product_name = " ''majorver'.''minorver'-''updatepatch'"
$ endif
$ product_line = product_line + " ''product_name' full"
$!
$!
$! If this is VAX and the file is on NFS, the names may be mangled.
$!-----------------------------------------------------------------
$ readme_file = ""
$ if f$search("[--]readme.") .nes. ""
$ then
$   readme_file = "[--]readme."
$ else
$   if f$search("[--]$README.") .nes. ""
$   then
$       readme_file = "[--]$README."
$   else
$       write sys$output "Can not find readme file."
$       goto all_exit
$   endif
$ endif
$ copying_file = ""
$ if f$search("[--]copying.") .nes. ""
$ then
$   copying_file = "[--]copying."
$ else
$   if f$search("[--]$COPYING.") .nes. ""
$   then
$       copying_file = "[--]$COPYING."
$   else
$       write sys$output "Can not find copying file."
$       goto all_exit
$   endif
$ endif
$!
$! Create the file as a VMS text file.
$!----------------------------------------
$ base_file = kit_name
$ create 'base_file'.pcsi$text
$!
$!
$! Start building file.
$!----------------------
$ open/append ptxt 'base_file'.pcsi$text
$ write ptxt product_line
$!
$!
$! First insert the Readme file.
$!
$ open/read rf 'readme_file'
$!
$ write ptxt "1 'PRODUCT"
$ write ptxt "=prompt ''producter' ''product' for OpenVMS"
$!
$rf_loop:
$   read/end=rf_loop_end rf line_in
$   if line_in .nes. ""
$   then
$!    PCSI files use the first character in for their purposes.
$!--------------------------------------------------------------
$     first_char = f$extract(0, 1, line_in)
$     if first_char .nes. " " then line_in = " " + line_in
$   endif
$   write ptxt line_in
$   goto rf_loop
$rf_loop_end:
$ close rf
$!
$!
$! Now add in the copying file
$!--------------------------------
$ write ptxt ""
$ write ptxt "1 'NOTICE"
$ write ptxt ""
$!
$ open/read cf 'copying_file'
$!
$cf_loop:
$   read/end=cf_loop_end cf line_in
$   if line_in .nes. ""
$   then
$!    PCSI files use the first character in for their purposes.
$!--------------------------------------------------------------
$     first_char = f$extract(0, 1, line_in)
$     if first_char .nes. " " then line_in = " " + line_in
$   endif
$   write ptxt line_in
$   goto cf_loop
$cf_loop_end:
$ close cf
$!
$! Now we need the rest of the boiler plate.
$!--------------------------------------------
$ write ptxt ""
$ write ptxt "1 'PRODUCER"
$ write ptxt "=prompt ''producer_full_name'"
$ write ptxt -
 "This software product is provided by ''producer_full_name' with no warranty."
$!
$ arch_type = f$getsyi("ARCH_NAME")
$ node_swvers = f$getsyi("node_swvers")
$ vernum = f$extract(1, f$length(node_swvers), node_swvers)
$ majver = f$element(0, ".", vernum)
$ minverdash = f$element(1, ".", vernum)
$ minver = f$element(0, "-", minverdash)
$ dashver = f$element(1, "-", minverdash)
$ if dashver .eqs. "-" then dashver = ""
$ vmstag = majver + minver + dashver
$ code = f$extract(0, 1, arch_type)
$!
$ write ptxt "1 NEED_VMS''vmstag'"
$ write ptxt -
   "=prompt OpenVMS ''vernum' or later is not installed on your system."
$ write ptxt "This product requires OpenVMS ''vernum' or later to function."
$ write ptxt "1 NEED_ZLIB"
$ write ptxt "=prompt ZLIB 1.2-8 or later is not installed on your system."
$ write ptxt "This product requires ZLIB 1.2-8 or later to function."
$ write ptxt "1 SOURCE"
$ write ptxt "=prompt Source modules for ''product'"
$ write ptxt "The Source modules for ''product' will be installed."
$ write ptxt "1 RELEASE_NOTES"
$ write ptxt "=prompt Release notes are available in the [SYSHLP] directory."
$!
$ close ptxt
$!
$!
$!
$all_exit:
$ exit
