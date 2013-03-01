$! File: config_h.com
$!
$! $Id: config_h.com,v 1.1.1.1 2012/12/02 19:25:21 wb8tyw Exp $
$!
$! This procedure attempts to figure out how to build a config.h file
$! for the current project.
$!
$! P1 specifies the config.h.in file or equivalent.  If it is not specified
$! then this procedure will search for several common names of the file.
$!
$! The CONFIGURE shell script will be examined for hints and a few symbols
$! but most of the tests will not produce valid results on OpenVMS.  Some
$! will produce false positives and some will produce false negatives.
$!
$! It is easier to just read the config.h_in file and make up tests based
$! on what is in it!
$!
$! This file will create an empty config_vms.h file if one does not exist.
$! The config_vms.h is intended for manual edits to handle things that
$! this procedure can not.
$!
$! The config_vms.h will be invoked by the resulting config.h file.
$!
$! This procedure knows about the DEC C RTL on the system it is on.
$! Future versions may be handle the GNV, the OpenVMS porting library,
$! and others.
$!
$! This procedure may not guess the options correctly for all architectures,
$! and is a work in progress.
$!
$! Copyright 2011, John Malmberg
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
$! 15-Jan-2001	J. Malmberg	Original
$! 29-Apr-2001	J. Malmberg	Also look for config.*in* in a [.include]
$!				subdirectory
$! 30-Apr-2001	J. Malmberg	Update for SAMBA checks
$! 09-Apr-2005	J. Malmberg	Update for RSYNC and large file.
$! 29-Sep-2011	J. Malmberg	Update for Bash 4.2
$! 01-Mar-2012	J. Malmberg	Warn about getcwd(0,0)
$! 21-Dec-2012	J. Malmberg	Update for gawk
$! 29-Dec-2012	J. Malmberg	Update for curl
$!============================================================================
$!
$ss_normal = 1
$ss_abort = 44
$ss_control_y = 1556
$status = ss_normal
$on control_y then goto control_y
$on warning then goto general_error
$!
$! Some information for writing timestamps to created files
$!----------------------------------------------------------
$my_proc = f$environment("PROCEDURE")
$my_proc_file = f$parse(my_proc,,,"NAME") + f$parse(my_proc,,,"TYPE")
$tab[0,8] = 9
$datetime = f$element(0,".",f$cvtime(,"ABSOLUTE","DATETIME"))
$username = f$edit(f$getjpi("","USERNAME"),"TRIM")
$!
$pid = f$getjpi("","PID")
$tfile1 = "SYS$SCRATCH:config_h_temp1_''pid'.TEMP"
$dchfile = "SYS$SCRATCH:config_h_decc_''pid'.TEMP"
$configure_script = "SYS$SCRATCH:configure_script_''pid'.TEMP"
$!
$!  Get the system type
$!----------------------
$arch_type = f$getsyi("arch_type")
$!
$!
$! Write out the header
$!----------------------
$gosub write_curlbuild_h_header
$!
$!
$! config.h.in could have at least five different names depending
$! on how it was transferred to OpenVMS
$!------------------------------------------------------------------
$base_curlbuild = "sys$disk:[.include.curl]"
$if p1 .nes. ""
$then
$   cfile = p1
$else
$   cfile = f$search("''base_curlbuild'curlbuild.h.in")
$   if cfile .eqs. ""
$   then
$	cfile = f$search("''base_curlbuild'curlbuild.h_in")
$	if cfile .eqs. ""
$	then
$	    cfile = f$search("''base_curlbuild'curlbuildh.in")
$	    if cfile .eqs. ""
$	    then
$		cfile = f$search("''base_curlbuild'curlbuild__2eh.in")
$		if cfile .eqs. ""
$		then
$		    cfile = f$search("''base_curlbuild'curlbuild.h__2ein")
$		    if cfile .eqs. ""
$		    then
$			cfile = f$search("''base_curlbuild'curlbuild.h$5nin")
$		    endif
$		endif
$	    endif
$	endif
$   endif
$endif
$!
$if cfile .eqs. ""
$then
$   write sys$output "Can not find ''base_curlbuild'curlbuild.h.in"
$   line_out = "Looked for curlbuild.h.in, curlbuild.h_in, curlbuild.in, "
$   line_out = line_out + "curlbuild__2eh.in, curlbuild.h__2ein, "
$   line_out = line_out + "curlbuild.h$5nin"
$   write/symbol sys$output line_out
$   goto general_error
$endif
$!
$open/read inf 'cfile'
$do_comment = 0
$if_block = 0
$cfgh_in_loop1:
$!set nover
$   read/end=cfgh_in_loop1_end inf line_in
$   xline = f$edit(line_in,"TRIM,COMPRESS")
$!
$!  Blank line handling
$!---------------------
$   if xline .eqs. ""
$   then
$	write tf ""
$	goto cfgh_in_loop1
$   endif
$   xlen = f$length(xline)
$   key = f$extract(0,2,xline)
$!
$!  deal with comments by copying exactly
$!-----------------------------------------
$   if (do_comment .eq. 1) .or. (key .eqs. "/*")
$   then
$	do_comment = 1
$	write tf line_in
$	key = f$extract(xlen - 2, 2, xline)
$	if key .eqs. "*/" then do_comment = 0
$	goto cfgh_in_loop1
$   endif
$!
$!  Some quick parsing
$!----------------------
$   keyif = f$extract(0,3,xline)
$   key1 = f$element(0," ",xline)
$   key2 = f$element(1," ",xline)
$   key2a = f$element(0,"_",key2)
$   key2b = f$element(1,"_",key2)
$   key2_len = f$length(key2)
$   key2_h = f$extract(key2_len - 2, 2, key2)
$   key2_t = f$extract(key2_len - 5, 5, key2)
$   if key2_t .eqs. "_TYPE" then key2_h = "_T"
$   key64 = 0
$   if f$locate("64", xline) .lt. xlen then key64 = 1
$!
$!write sys$output "xline = ''xline'"
$!
$   if key1 .nes. "#undef"
$   then
$	write tf line_in
$	goto cfgh_in_loop1
$   endif
$!
$!  All versions of VMS have sys/types.h
$!----------------------------------------
$   if (key2 .eqs. "CURL_PULL_SYS_TYPES_H")
$   then
$	write tf "#define ''key2' 1"
$	goto cfgh_in_loop1
$   endif
$!
$!  Most have sys/socket.h
$!-------------------------
$   if (key2 .eqs. "CURL_PULL_SYS_SOCKET_H")
$   then
$	write tf "#ifdef HAVE_SYS_SOCKET_H"
$	write tf "#define ''key2' 1"
$	write tf "#else"
$	write tf "#undef ''key2'"
$	write tf "#endif"
$	goto cfgh_in_loop1
$   endif
$!
$!  VAX/VMS 7.3 does not have sys/poll.h
$!----------------------------------------
$   if (key2 .eqs. "CURL_PULL_SYS_POLL_H")
$   then
$	write tf "#ifdef HAVE_POLL_H"
$	write tf "#define ''key2' 1"
$	write tf "#else"
$	write tf "#undef ''key2'"
$	write tf "#endif"
$	goto cfgh_in_loop1
$   endif
$!
$   if (key2 .eqs. "CURL_SIZEOF_LONG")
$   then
$	write tf "#define ''key2' SIZEOF_INT"
$	goto cfgh_in_loop1
$   endif
$!
$   if (key2 .eqs. "CURL_SIZEOF_CURL_SOCKLEN_T")
$   then
$	write tf "#define ''key2' SIZEOF_INT"
$	goto cfgh_in_loop1
$   endif
$!
$   if (key2 .eqs. "CURL_TYPEOF_CURL_SOCKLEN_T")
$   then
$	write tf "#define ''key2' size_t"
$	goto cfgh_in_loop1
$   endif
$!
$   if (key2 .eqs. "CURL_TYPEOF_CURL_OFF_T")
$   then
$	write tf "#define ''key2' off_t"
$	goto cfgh_in_loop1
$   endif
$!
$   if (key2 .eqs. "CURL_FORMAT_CURL_OFF_T")
$   then
$	write tf "#if (SIZEOF_OFF_T == 8)"
$	write tf "#define ''key2' ""lld"""
$	write tf "#else"
$	write tf "#define ''key2' ""ld"""
$	write tf "#endif"
$	goto cfgh_in_loop1
$   endif
$!
$   if (key2 .eqs. "CURL_FORMAT_CURL_OFF_TU")
$   then
$	write tf "#if (SIZEOF_OFF_T == 8)"
$	write tf "#define ''key2' ""llu"""
$	write tf "#else"
$	write tf "#define ''key2' ""lu"""
$	write tf "#endif"
$	goto cfgh_in_loop1
$   endif
$!
$   if (key2 .eqs. "CURL_FORMAT_OFF_T")
$   then
$	write tf "#if (SIZEOF_OFF_T == 8)"
$	write tf "#define ''key2' ""%lld"""
$	write tf "#else"
$	write tf "#define ''key2' ""%ld"""
$	write tf "#endif"
$	goto cfgh_in_loop1
$   endif
$!
$   if (key2 .eqs. "CURL_SIZEOF_CURL_OFF_T")
$   then
$	write tf "#define ''key2' SIZEOF_OFF_T"
$	goto cfgh_in_loop1
$   endif
$!
$   if (key2 .eqs. "CURL_SUFFIX_CURL_OFF_T")
$   then
$	write tf "#if (SIZEOF_OFF_T == 8)"
$	write tf "#define ''key2' LL"
$	write tf "#else"
$	write tf "#define ''key2' L"
$	write tf "#endif"
$	goto cfgh_in_loop1
$   endif
$!
$   if (key2 .eqs. "CURL_SUFFIX_CURL_OFF_TU")
$   then
$	write tf "#if (SIZEOF_OFF_T == 8)"
$	write tf "#define ''key2' ULL"
$	write tf "#else"
$	write tf "#define ''key2' UL"
$	write tf "#endif"
$	goto cfgh_in_loop1
$   endif
$!
$!
$!
$!  If it falls through everything else, comment it out
$!-----------------------------------------------------
$   write tf "/* ", xline, " */"
$   goto cfgh_in_loop1
$cfgh_in_loop1_end:
$close inf
$close tf
$!
$! Exit and clean up
$!--------------------
$general_error:
$status = '$status'
$all_exit:
$set noon
$if f$trnlnm("tf","lnm$process",,"SUPERVISOR") .nes. "" then close tf
$if f$trnlnm("inf","lnm$process",,"SUPERVISOR") .nes. "" then close inf
$exit 'status'
$!
$!
$control_y:
$   status = ss_control_y
$   goto all_exit
$!
$!
$! gosub to write out a documentation header for config.h
$!----------------------------------------------------------------
$write_curlbuild_h_header:
$outfile = "sys$disk:[.include.curl]curlbuild.h"
$create 'outfile'
$open/append tf 'outfile'
$write tf -
 "/* [.include.curl]curlbuild.h.  Generated from curlbuild.h.in by */"
$write tf -
 "/* ", my_proc_file, tab, datetime, tab, username, tab, "         */"
$write tf ""
$return
