$! File: Build_GNV_CURL_PCSI_DESC.COM
$!
$! $Id$
$!
$! Build the *.pcsi$text file in the following sections:
$!   Required software dependencies.
$!   install/upgrade/postinstall steps.
$!      1. Duplicate filenames need an alias procedure. (N/A for curl)
$!      2. ODS-5 filenames need an alias procedure. (N/A for curl)
$!      3. Special alias links for executables (curl. -> curl.exe)
$!         if a lot, then an alias procedure is needed.
$!      4. Rename the files to lowercase.
$!   Move Release Notes to destination
$!   Source kit option
$!   Create directory lines
$!   Add file lines for curl.
$!   Add Link alias procedure file (N/A for curl)
$!   Add [.SYS$STARTUP]curl_startup file
$!   Add Release notes file.
$!
$! The file PCSI_GNV_CURL_FILE_LIST.TXT is read in to get the files other
$! than the release notes file and the source backup file.
$!
$! The PCSI system can really only handle ODS-2 format filenames and
$! assumes that there is only one source directory.  It also assumes that
$! all destination files with the same name come from the same source file.
$! Fortunately CURL does not trip most of these issues, so those steps
$! above are marked N/A.
$!
$! A rename action section is needed to make sure that the files are
$! created in the GNV$GNU: in the correct case, and to create the alias
$! link [usr.bin]curl. for [usr.bin]curl.exe.
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
$ filename_base = f$trnlnm("GNV_PCSI_FILENAME_BASE")
$ if filename_base .eqs. ""
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
$! kit type of "D" means a daily build
$ kit_type = f$edit(f$extract(0, 1, majorver), "upcase")
$!
$!
$ product_line = "product ''producer' ''base' ''product'"
$ if updatepatch .eqs. ""
$ then
$     product_name = " ''majorver'.''minorver'"
$ else
$     product_name = " ''majorver'.''minorver'-''updatepatch'"
$ endif
$ product_line = product_line + " ''product_name' full;"
$!write sys$output product_line
$!
$!
$!
$! Create the file as a VMS text file.
$!----------------------------------------
$ base_file = kit_name
$ create 'base_file'.pcsi$desc
$!
$!
$! Start building file.
$!----------------------
$ open/append pdsc 'base_file'.pcsi$desc
$!
$ write pdsc product_line
$!
$! Required product dependencies.
$!----------------------------------
$ vmsprd = "DEC"
$ if base .eqs. "I64VMS" then vmsprd = "HP"
$ vsiprd = "VSI"
$!
$ write pdsc "   software ''vmsprd' ''base' VMS ;"
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
$ arch_code = f$extract(0, 1, arch_type)
$ line_out = -
 "   if ((not <software ''vsiprd' ''base' VMS version minimum" + -
 " ''node_swvers'>) and" + -
 " (not <software ''vmsprd' ''base' VMS version minimum ''node_swvers'>));"
$ write pdsc line_out
$ write pdsc "      error NEED_VMS''vmstag';"
$ write pdsc "   end if;"
$!
$write pdsc "   software VMSPORTS ''base' ZLIB ;"
$write pdsc -
    "   if (not <software VMSPORTS ''base' ZLIB version minimum V1.2-8>) ;"
$write pdsc "      error NEED_ZLIB;"
$write pdsc "   end if;"
$!
$!
$!
$! install/upgrade/postinstall steps.
$!-----------------------------------
$!      1. Duplicate filenames need an alias procedure. (N/A for curl)
$!      2. ODS-5 filenames need an alias procedure. (N/A for curl)
$!      3. Special alias links for executables (curl. -> curl.exe)
$!         if a lot, then an alias procedure is needed.
$!      4. Rename the files to lowercase.
$!
$!
$!   Alias links needed.
$!-------------------------
$ add_alias_lines = ""
$ rem_alias_lines = ""
$ line_out = ""
$!
$!   Read through the file list to set up aliases and rename commands.
$!---------------------------------------------------------------------
$ open/read flst pcsi_gnv_curl_file_list.txt
$!
$inst_alias_loop:
$   read/end=inst_alias_loop_end flst line_in
$   line_in = f$edit(line_in,"compress,trim,uncomment")
$   if line_in .eqs. "" then goto inst_alias_loop
$   pathname = f$element(0, " ", line_in)
$   linkflag = f$element(1, " ", line_in)

$   if linkflag .nes. "->" then goto inst_alias_write
$!
$   linktarget = f$element(2, " ", line_in)
$   if kit_type .eqs. "D"
$   then
$       old_start = f$locate("[gnv.usr", pathname)
$       if old_start .lt. f$length(pathname)
$       then
$           pathname = "[gnv.beta" + pathname - "[gnv.usr"
$           linktarget = "[gnv.beta" + linktarget - "[gnv.usr"
$       endif
$   endif
$   nlink = "pcsi$destination:" + pathname
$   ntarg = "pcsi$destination:" + linktarget
$   new_add_alias_line = -
  """if f$search(""""''nlink'"""") .eqs. """""""" then" + -
  " set file/enter=''nlink' ''ntarg'"""
$   if add_alias_lines .nes. ""
$   then
$       add_alias_lines = add_alias_lines + "," + new_add_alias_line
$   else
$       add_alias_lines = new_add_alias_line
$   endif
$!
$   new_rem_alias_line = -
  """if f$search(""""''nlink'"""") .nes. """""""" then" + -
  " set file/remove ''nlink';"""
$   if rem_alias_lines .nes. ""
$   then
$      rem_alias_lines = rem_alias_lines + "," + new_rem_alias_line
$   else
$      rem_alias_lines = new_rem_alias_line
$   endif
$!
$   goto inst_alias_loop
$!
$inst_alias_write:
$!
$!  execute install / remove
$   write pdsc "   execute install ("
$! add aliases
$   i = 0
$ex_ins_loop:
$       line = f$element(i, ",", add_alias_lines)
$       i = i + 1
$       if line .eqs. "" then goto ex_ins_loop
$       if line .eqs. "," then goto ex_ins_loop_end
$       if line_out .nes. "" then write pdsc line_out,","
$       line_out = line
$       goto ex_ins_loop
$ex_ins_loop_end:
$   write pdsc line_out
$   line_out = ""
$   write pdsc "      )"
$   write pdsc "   remove ("
$! remove aliases
$   i = 0
$ex_rem_loop:
$       line = f$element(i, ",", rem_alias_lines)
$       i = i + 1
$       if line .eqs. "" then goto ex_rem_loop
$       if line .eqs. "," then goto ex_rem_loop_end
$       if line_out .nes. "" then write pdsc line_out,","
$       line_out = line
$       goto ex_rem_loop
$ex_rem_loop_end:
$   write pdsc line_out
$   line_out = ""
$   write pdsc "      ) ;"
$!
$!  execute upgrade
$   write pdsc "   execute upgrade ("
$   i = 0
$ex_upg_loop:
$       line = f$element(i, ",", rem_alias_lines)
$       i = i + 1
$       if line .eqs. "" then goto ex_upg_loop
$       if line .eqs. "," then goto ex_upg_loop_end
$       if line_out .nes. "" then write pdsc line_out,","
$       line_out = line
$       goto ex_upg_loop
$ex_upg_loop_end:
$   write pdsc line_out
$   line_out = ""
$! remove aliases
$   write pdsc "      ) ;"
$!
$!  execute postinstall
$   write pdsc "   execute postinstall ("
$   if arch_code .nes. "V"
$   then
$       line_out = "   ""set process/parse=extended"""
$   endif
$   i = 0
$ex_pins_loop:
$       line = f$element(i, ",", add_alias_lines)
$       i = i + 1
$       if line .eqs. "" then goto ex_pins_loop
$       if line .eqs. "," then goto ex_pins_loop_end
$       if line_out .nes. "" then write pdsc line_out,","
$       line_out = line
$       goto ex_pins_loop
$ex_pins_loop_end:
$   if line_out .eqs. "" then line_out = "   ""continue"""
$!   write pdsc line_out
$!   line_out = ""
$! add aliases and follow with renames.
$!
$goto inst_dir
$!
$inst_dir_loop:
$   read/end=inst_alias_loop_end flst line_in
$   line_in = f$edit(line_in,"compress,trim,uncomment")
$   if line_in .eqs. "" then goto inst_dir_loop
$inst_dir:
$   pathname = f$element(0, " ", line_in)
$   if kit_type .eqs. "D"
$   then
$       if pathname .eqs. "[gnv]usr.dir"
$       then
$           pathname = "[gnv]beta.dir"
$       else
$           old_start = f$locate("[gnv.usr", pathname)
$           if old_start .lt. f$length(pathname)
$           then
$               pathname = "[gnv.beta" + pathname - "[gnv.usr"
$           endif
$       endif
$   endif
$!
$!  Ignore the directory entries for now.
$!-----------------------------------------
$   filedir = f$parse(pathname,,,"DIRECTORY")
$   if pathname .eqs. filedir then goto inst_dir_loop
$!
$!  process .dir extensions for rename
$!  If this is not a directory then start processing files.
$!-------------------------
$   filetype = f$parse(pathname,,,"TYPE")
$   filetype_u = f$edit(filetype, "upcase")
$   filename = f$parse(pathname,,,"NAME")
$   if filetype_u .nes. ".DIR" then goto inst_file
$!
$!  process directory lines for rename.
$!--------------------------------------
$   if line_out .nes. ""
$   then
$       write pdsc line_out,","
$       line_out = ""
$   endif
$   if arch_code .nes. "V"
$   then
$       if line_out .nes. "" then write pdsc line_out,","
$       line_out = "   ""rename pcsi$destination:''pathname' ''filename'.DIR"""
$   else
$       if line_out .nes. "" then write pdsc line_out
$       line_out = ""
$   endif
$   goto inst_dir_loop
$!
$!
$!   process file lines for rename
$!---------------------------------
$inst_file_loop:
$   read/end=inst_alias_loop_end flst line_in
$   line_in = f$edit(line_in,"compress,trim,uncomment")
$   if line_in .eqs. "" then goto inst_dir_loop
$   pathname = f$element(0, " ", line_in)
$   if kit_type .eqs. "D"
$   then
$       if pathname .eqs. "[gnv]usr.dir"
$       then
$           pathname = "[gnv]beta.dir"
$       else
$           old_start = f$locate("[gnv.usr", pathname)
$           if old_start .lt. f$length(pathname)
$           then
$               pathname = "[gnv.beta" + pathname - "[gnv.usr"
$           endif
$       endif
$   endif
$!
$!  Filenames with $ in them are VMS special and do not need to be lowercase.
$!  --------------------------------------------------------------------------
$   if f$locate("$", pathname) .lt. f$length(pathname) then goto inst_file_loop
$!
$   filetype = f$parse(pathname,,,"TYPE")
$   filename = f$parse(pathname,,,"NAME") + filetype
$inst_file:
$   if arch_code .nes. "V"
$   then
$       if line_out .nes. "" then write pdsc line_out,","
$       filetype = f$parse(pathname,,,"TYPE")
$       filename = f$parse(pathname,,,"NAME") + filetype
$       line_out = "   ""rename pcsi$destination:''pathname' ''filename'"""
$   else
$       if line_out .nes. "" then write pdsc line_out
$       line_out = ""
$   endif
$   goto inst_file_loop
$!
$inst_alias_loop_end:
$!
$write pdsc line_out
$write pdsc "        ) ;"
$close flst
$!
$!   Move Release Notes to destination
$!-------------------------------------
$write pdsc "   information RELEASE_NOTES phase after ;"
$!
$!   Source kit option
$!---------------------
$write pdsc "   option SOURCE default 0;"
$write pdsc "   directory ""[gnv.common_src]"" PROTECTION PUBLIC ;"
$write pdsc -
    "        file ""[gnv.common_src]''filename_base'_original_src.bck"""
$write pdsc -
    "          source [common_src]''filename_base'_original_src.bck ;"
$if f$search("gnv$gnu:[vms_src]''filename_base'_vms_src.bck") .nes. ""
$then
$    write pdsc "   directory ""[gnv.vms_src]"" PROTECTION PUBLIC ;"
$    write pdsc "        file ""[gnv.vms_src]''filename_base'_vms_src.bck"""
$    write pdsc "          source [vms_src]''filename_base'_vms_src.bck ;"
$endif
$write pdsc "   end option;"
$!
$!
$! Read through the file list again.
$!----------------------------------
$open/read flst pcsi_gnv_curl_file_list.txt
$!
$!
$!   Create directory lines
$!-------------------------
$flst_dir_loop:
$   read/end=flst_loop_end flst line_in
$   line_in = f$edit(line_in,"compress,trim,uncomment")
$   if line_in .eqs. "" then goto flst_dir_loop
$!
$   filename = f$element(0, " ", line_in)
$   linkflag = f$element(1, " ", line_in)
$   if linkflag .eqs. "->" then goto flst_dir_loop
$!
$!  Ignore .dir extensions
$!-------------------------
$   filetype = f$edit(f$parse(filename,,,"TYPE"), "upcase")
$   if filetype .eqs. ".DIR" then goto flst_dir_loop
$!
$   destname = filename
$   if kit_type .eqs. "D"
$   then
$       old_start = f$locate("[gnv.usr", destname)
$       if old_start .lt. f$length(destname)
$       then
$           destname = "[gnv.beta" + destname - "[gnv.usr"
$       endif
$   endif
$!
$!  It should be just a directory then.
$!-------------------------------------
$   filedir = f$edit(f$parse(filename,,,"DIRECTORY"), "lowercase")
$!  If this is not a directory then start processing files.
$!---------------------------------------------------------
$   if filename .nes. filedir then goto flst_file
$!
$   write pdsc "   directory ""''destname'"" PROTECTION PUBLIC ;"
$   goto flst_dir_loop
$!
$!
$!   Add file lines for curl.
$!---------------------------
$flst_file_loop:
$   read/end=flst_loop_end flst line_in
$   line_in = f$edit(line_in,"compress,trim,uncomment")
$   if line_in .eqs. "" then goto inst_file_loop
$   filename = f$element(0, " ", line_in)
$   destname = filename
$   if kit_type .eqs. "D"
$   then
$       old_start = f$locate("[gnv.usr", destname)
$       if old_start .lt. f$length(destname)
$       then
$           destname = "[gnv.beta" + destname - "[gnv.usr"
$       endif
$   endif
$flst_file:
$   srcfile = filename - "gnv."
$   write pdsc "   file ""''destname'"" "
$   write pdsc "     source ""''srcfile'"" ;"
$   goto flst_file_loop
$!
$flst_loop_end:
$ close flst
$!
$!   Add Link alias procedure file (N/A for curl)
$!------------------------------------------------
$!
$!   Add [.SYS$STARTUP]curl_startup file
$!---------------------------------------
$ if kit_type .eqs. "D"
$ then
$   write pdsc "   file ""[sys$startup]curl_daily_startup.com"""
$ else
$   write pdsc "   file ""[sys$startup]curl_startup.com"""
$ endif
$ write pdsc "     source [usr.lib]curl_startup.com ;"
$!
$!   Add Release notes file.
$!------------------------------
$ write pdsc -
    "   file ""[SYSHLP]''filename_base'.release_notes"" release notes ;"
$!
$! Close the product file
$!------------------------
$ write pdsc "end product;"
$!
$close pdsc
$!
$all_exit:
$ exit
