$! File: config_h.com
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
$!============================================================================
$!
$ss_normal = 1
$ss_abort = 44
$ss_control_y = 1556
$status = ss_normal
$on control_y then goto control_y
$on warning then goto general_error
$!on warning then set ver
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
$starhfile = "SYS$SCRATCH:config_h_starlet_''pid'.TEMP"
$configure_script = "SYS$SCRATCH:configure_script_''pid'.TEMP"
$!
$!  Get the system type
$!----------------------
$arch_type = f$getsyi("arch_type")
$!
$! Does config_vms.h exist?
$!-------------------------
$update_config_vms = 0
$file = f$search("sys$disk:[]config_vms.h")
$if file .nes. ""
$then
$   write sys$output "Found existing custom file ''file'."
$else
$   update_config_vms = 1
$   write sys$output "Creating new sys$disk:[]config_vms.h for you."
$   gosub write_config_vms
$endif
$!
$!
$! On some platforms, DCL search has problems with searching a file
$! on a NFS mounted volume.  So copy it to sys$scratch:
$!
$if f$search(configure_script) .nes. "" then delete 'configure_script';*
$copy sys$disk:[]configure 'configure_script'
$!
$ssl_header_dir = "OPENSSL:"
$if f$trnlnm("OPENSSL") .eqs. ""
$then
$    ssl_header_dir = "SSL$INCLUDE:"
$endif
$!
$!
$! Write out the header
$!----------------------
$gosub write_config_h_header
$!
$!
$!
$! config.h.in could have at least five different names depending
$! on how it was transferred to OpenVMS
$!------------------------------------------------------------------
$if p1 .nes. ""
$then
$   cfile = p1
$else
$   cfile = f$search("sys$disk:[]config.h.in")
$   if cfile .eqs. ""
$   then
$       cfile = f$search("sys$disk:[]config.h_in")
$       if cfile .eqs. ""
$       then
$           cfile = f$search("sys$disk:[]configh.in")
$           if cfile .eqs. ""
$           then
$               cfile = f$search("sys$disk:[]config__2eh.in")
$               if cfile .eqs. ""
$               then
$                   cfile = f$search("sys$disk:[]config.h__2ein")
$               endif
$           endif
$       endif
$   endif
$endif
$if f$trnlnm("PRJ_INCLUDE") .nes. ""
$then
$   cfile = f$search("PRJ_INCLUDE:config.h.in")
$   if cfile .eqs. ""
$   then
$       cfile = f$search("PRJ_INCLUDE:config.h_in")
$       if cfile .eqs. ""
$       then
$           cfile = f$search("PRJ_INCLUDE:config__2eh.in")
$           if cfile .eqs. ""
$           then
$               cfile = f$search("PRJ_INCLUDE:config__2eh.in")
$               if cfile .eqs. ""
$               then
$                   cfile = f$search("PRJ_INCLUDE:config.h__2ein")
$               endif
$           endif
$       endif
$    endif
$endif
$if cfile .eqs. ""
$then
$   write sys$output "Can not find sys$disk:config.h.in"
$   line_out = "Looked for config.h.in, config.h_in, configh.in, "
$   line_out = line_out + "config__2eh.in, config.h__2ein"
$   write/symbol sys$output line_out
$   if f$trnlnm("PRJ_INCLUDE") .nes. ""
$   then
$       write sys$output "Also looked in PRJ_INCLUDE: for these files."
$   endif
$!
$   write tf ""
$   write tf -
        "   /* Could not find sys$disk:config.h.in                           */"
$   write tf -
        "  /*  Looked also for config.h_in, configh.in, config__2eh.in,     */"
$   write tf -
        " /*   config.h__2ein                                              */"
$   if f$trnlnm("PRJ_INCLUDE") .nes. ""
$   then
$       write tf -
        " /* Also looked in PRJ_INCLUDE: for these files.                 */"
$   endif
$   write tf -
        "/*--------------------------------------------------------------*/
$   write tf ""
$   goto write_tail
$endif
$!
$!
$! Locate the DECC libraries in use
$!-----------------------------------
$decc_rtldef = f$parse("decc$rtldef","sys$library:.tlb;0")
$decc_starletdef = f$parse("sys$starlet_c","sys$library:.tlb;0")
$decc_shr = f$parse("decc$shr","sys$share:.exe;0")
$!
$! Dump the DECC header names into a file
$!----------------------------------------
$if f$search(dchfile) .nes. "" then delete 'dchfile';*
$if f$search(tfile1) .nes. "" then delete 'tfile1';*
$define/user sys$output 'tfile1'
$library/list 'decc_rtldef'
$open/read/error=rtldef_loop1_end tf1 'tfile1'
$open/write/error=rtldef_loop1_end tf2 'dchfile'
$rtldef_loop1:
$   read/end=rtldef_loop1_end tf1 line_in
$   line_in = f$edit(line_in,"TRIM,COMPRESS")
$   key1 = f$element(0," ",line_in)
$   key2 = f$element(1," ",line_in)
$   if key1 .eqs. " " .or. key1 .eqs. "" then goto rtldef_loop1
$   if key2 .nes. " " .and. key2 .nes. "" then goto rtldef_loop1
$   write tf2 "|",key1,"|"
$   goto rtldef_loop1
$rtldef_loop1_end:
$if f$trnlnm("tf1","lnm$process",,"SUPERVISOR") .nes. "" then close tf1
$if f$trnlnm("tf2","lnm$process",,"SUPERVISOR") .nes. "" then close tf2
$if f$search(tfile1) .nes. "" then delete 'tfile1';*
$!
$! Dump the STARLET header names into a file
$!----------------------------------------
$if f$search(starhfile) .nes. "" then delete 'starhfile';*
$if f$search(tfile1) .nes. "" then delete 'tfile1';*
$define/user sys$output 'tfile1'
$library/list 'decc_starletdef'
$open/read/error=stardef_loop1_end tf1 'tfile1'
$open/write/error=stardef_loop1_end tf2 'starhfile'
$stardef_loop1:
$   read/end=stardef_loop1_end tf1 line_in
$   line_in = f$edit(line_in,"TRIM,COMPRESS")
$   key1 = f$element(0," ",line_in)
$   key2 = f$element(1," ",line_in)
$   if key1 .eqs. " " .or. key1 .eqs. "" then goto stardef_loop1
$   if key2 .nes. " " .and. key2 .nes. "" then goto stardef_loop1
$   write tf2 "|",key1,"|"
$   goto stardef_loop1
$stardef_loop1_end:
$if f$trnlnm("tf1","lnm$process",,"SUPERVISOR") .nes. "" then close tf1
$if f$trnlnm("tf2","lnm$process",,"SUPERVISOR") .nes. "" then close tf2
$if f$search(tfile1) .nes. "" then delete 'tfile1';*
$!
$!
$! Now calculate what should be in the file from reading
$! config.h.in and CONFIGURE.
$!---------------------------------------------------------------
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
$       write tf ""
$       goto cfgh_in_loop1
$   endif
$   xlen = f$length(xline)
$   key = f$extract(0,2,xline)
$!
$!  deal with comments by copying exactly
$!-----------------------------------------
$   if (do_comment .eq. 1) .or. (key .eqs. "/*")
$   then
$       do_comment = 1
$       write tf line_in
$       key = f$extract(xlen - 2, 2, xline)
$       if key .eqs. "*/" then do_comment = 0
$       goto cfgh_in_loop1
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
$!  Comment out this section of the ifblock
$!-----------------------------------------
$   if if_block .ge. 3
$   then
$       write tf "/* ", xline, " */"
$       if keyif .eqs. "#en" then if_block = 0
$       goto cfgh_in_loop1
$   endif
$!
$!  Handle the end of an ifblock
$!-------------------------------
$   if keyif .eqs. "#en"
$   then
$       write tf xline
$       if_block = 0
$       goto cfgh_in_loop1
$   endif
$!
$   if key1 .eqs. "#ifndef"
$   then
$!      Manual check for _ALL_SOURCE on AIX error
$!-----------------------------------------------
$       if key2 .eqs. "_ALL_SOURCE"
$       then
$          write tf "/* ", xline, " */"
$!
$!         Ignore the rest of the block
$!--------------------------------------
$          if_block = 3
$          goto cfgh_in_loop1
$       endif
$   endif
$!
$!
$!  Default action for an #if/#else/#endif
$!------------------------------------------
$   if keyif .eqs. "#if" .or. keyif .eqs. "#el"
$   then
$       if_block = 1
$       write tf xline
$       goto cfgh_in_loop1
$   endif
$!
$!
$!  Process "normal?" stuff
$!---------------------------
$   if key1 .eqs. "#undef"
$   then
$       key2c = f$element(2, "_", key2)
$       if (key2c .eqs. "_") .or. (key2c .eqs. "H") then key2c = ""
$       key2d = f$element(3, "_", key2)
$       if (key2d .eqs. "_") .or. (key2d .eqs. "H") then key2d = ""
$       key2e = f$element(4, "_", key2)
$       if (key2e .eqs. "_") .or. (key2e .eqs. "H") then key2e = ""
$       if key2d .eqs. "T"
$       then
$           if key2e .eqs. "TYPE"
$           then
$               key2_h = "_T"
$               key2d = ""
$           endif
$       endif
$!
$       double_under = 0
$!
$!      Process FCNTL directives
$!-------------------------------------
$       if (key2b .eqs. "FCNTL") .and. (key2c .eqs. "O") .and. -
           (key2d .eqs. "NONBLOCK")
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$!      Process GETADDRINFO directives
$!-------------------------------------
$       if key2 .eqs. "GETADDRINFO_THREADSAFE"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$!      Process IOCTL directives
$!-------------------------------------
$       if (key2b .eqs. "IOCTL") .and. (key2c .nes. "")
$       then
$           if (key2c .eqs. "FIONBIO") .or. (key2c .eqs. "SIOCGIFADDR")
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' 1"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$       endif
$!
$!
$!      Manual check for LL on
$!-----------------------------------------------
$       if key2 .eqs. "LL"
$       then
$          write tf "#ifndef __VAX
$          write tf "#define HAVE_''key2' 1"
$          write tf "#endif"
$          goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "bool_t"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' short"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "bits16_t"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' short"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "u_bits16_t"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' unsigned short"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "bits32_t"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' int"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "u_bits32_t"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' unsigned int"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "intmax_t"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#ifdef __VAX"
$           write tf "#define ''key2' long"
$           write tf "#else"
$           write tf "#define ''key2' long long"
$           write tf "#endif"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "uintmax_t"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#ifdef __VAX"
$           write tf "#define ''key2' unsigned long"
$           write tf "#else"
$           write tf "#define ''key2' unsigned long long"
$           write tf "#endif"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "socklen_t"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' int"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "GETGROUPS_T"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' gid_t"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_DECL_SYS_SIGLIST"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 0"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_SYS_ERRLIST"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_STRUCT_DIRENT_D_INO"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_STRUCT_TIMEVAL"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$!      ! The header files have this information, however
$!      ! The ioctl() call only works on sockets.
$!      if key2 .eqs. "FIONREAD_IN_SYS_IOCTL"
$!      then
$!          write tf "#ifndef ''key2'"
$!          write tf "#define ''key2' 1"
$!          write tf "#endif"
$!          goto cfgh_in_loop1
$!      endif
$!
$!      ! The header files have this information, however
$!      ! The ioctl() call only works on sockets.
$!      if key2 .eqs. "GWINSZ_IN_SYS_IOCTL"
$!      then
$!          write tf "#ifndef ''key2'"
$!          write tf "#define ''key2' 1"
$!          write tf "#endif"
$!          goto cfgh_in_loop1
$!      endif
$!
$!      ! The header files have this information, however
$!      ! The ioctl() call only works on sockets.
$!      if key2 .eqs. "STRUCT_WINSIZE_IN_SYS_IOCTL"
$!      then
$!          write tf "#ifndef ''key2'"
$!          write tf "#define ''key2' 0"
$!          write tf "#endif"
$!          goto cfgh_in_loop1
$!      endif
$!
$       if key2 .eqs. "HAVE_STRUCT_TM_TM_ZONE"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_TM_ZONE"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_TIMEVAL"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "WEXITSTATUS_OFFSET"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 2"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_GETPW_DECLS"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_DECL_CONFSTR"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_DECL_PRINTF"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_DECL_SBRK"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_DECL_STRSIGNAL"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 0"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2a .eqs. "HAVE_DECL_STRTOLD"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 0"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_DECL_STRTOIMAX"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 0"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_DECL_STRTOL"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_DECL_STRTOUL"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_DECL_STRTOUMAX"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 0"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "GETPGRP_VOID"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "NAMED_PIPES_MISSING"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "OPENDIR_NOT_ROBUST"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "PGRP_PIPE"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "CAN_REDEFINE_GETENV"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_PRINTF_A_FORMAT"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "CTYPE_NON_ASCII"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_LANGINFO_CODESET"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 0"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$!      This wants execve() to do this automagically to pass.
$!      if key2 .eqs. "HAVE_HASH_BANG_EXEC"
$!      then
$!          write tf "#ifndef ''key2'"
$!          write tf "#define ''key2' 1"
$!          write tf "#endif"
$!          goto cfgh_in_loop1
$!      endif
$!
$       if key2 .eqs. "ICONV_CONST"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2'"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "VOID_SIGHANDLER"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_POSIX_SIGNALS"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "UNUSABLE_RT_SIGNALS"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2a .eqs. "HAVE_DECL_FPURGE"
$       then
$           write tf "#ifndef ''key2a'"
$           write tf "#define ''key2a' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_DECL_SETREGID"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "HAVE_POSIX_SIGSETJMP"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2b .eqs. "RAND" .and. key2c .nes. "" .and. key2d .eqs. ""
$       then
$           if (key2c .eqs. "EGD") .or. -
               (key2c .eqs. "STATUS") .or. -
               (key2c .eqs. "SCREEN")
$           then
$               if f$search("''ssl_header_dir'rand.h") .nes. ""
$               then
$                   write tf "#ifndef ''key2'"
$                   write tf "#define ''key2' 1"
$                   write tf "#endif"
$               else
$                   write tf "/* #undef ''key2' */"
$               endif
$           endif
$       endif
$!
$       if key2 .eqs. "STRCOLL_BROKEN"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$       if key2 .eqs. "DUP_BROKEN"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#define ''key2' 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$!      This is for a test that getcwd(0,0) works.
$!      It does not on VMS.
$!--------------------------
$       if key2 .eqs. "GETCWD_BROKEN"
$       then
$           write sys$output ""
$           write sys$output -
  "%CONFIG_H-I-NONPORT, ''key2' being tested for!"
$                  write sys$output -
 "-CONFIG_H-I-GETCWD, GETCWD(0,0) does not work on VMS."
$                  write sys$output -
 "-CONFIG_H-I-GETCWD2, Work around hack probably required."
$                  write sys$output -
 "-CONFIG_H-I-REVIEW, Manual Code review required!"
$                   if update_config_vms
$                   then
$                       open/append tfcv sys$disk:[]config_vms.h
$                       write tfcv ""
$                       write tfcv -
                "/* Check config.h for use of ''key2' settings */"
$                       write tfcv ""
$                       close tfcv
$                   endif
$
$           goto cfgh_in_loop1
$       endif
$!
$       if (key2a .eqs. "HAVE") .or. (key2a .eqs. "STAT") .or. -
           (key2 .eqs. "USE_IPV6") .or. (key2b .eqs. "LDAP")
$       then
$!
$!          Process extra underscores
$!------------------------------------
$           if f$locate("HAVE___", key2) .lt. key2_len
$           then
$               key2b = "__" + key2d
$               key2d = ""
$               double_under = 1
$           else
$               if f$locate("HAVE__", key2) .lt. key2_len
$               then
$                   key2b = "_" + key2c
$                   key2c = ""
$                   double_under = 1
$               endif
$           endif
$!
$           if (key2_h .eqs. "_H") .or. (key2 .eqs. "USE_IPV6") .or. -
               (key2b .eqs. "LDAP")
$           then
$!
$!              Looking for a header file
$!---------------------------------------
$               headf = key2b
$               if key2c .nes. "" then headf = headf + "_" + key2c
$               if key2d .nes. "" then headf = headf + "_" + key2d
$!
$!                 (key2b .eqs. "READLINE")
$!
$!              Some special parsing
$!------------------------------------------
$               if (key2b .eqs. "SYS") .or. (key2b .eqs. "ARPA") .or. -
                   (key2b .eqs. "NET") .or. (key2b .eqs. "NETINET")
$               then
$                   if key2c .nes. ""
$                   then
$                       headf = key2c
$                       if key2d .nes. "" then headf = key2c + "_" + key2d
$                   endif
$               endif
$!
$!              And of course what's life with out some special cases
$!--------------------------------------------------------------------
$               if key2 .eqs. "USE_IPV6"
$               then
$                   headf = "in6"
$               endif
$!
$               if key2b .eqs. "LDAP"
$               then
$                   if (key2 .eqs. "HAVE_LDAP_SSL") .or. -
                       (key2 .eqs. "HAVE_LDAP_URL_PARSE")
$                   then
$                       headf = "ldap"
$                   endif
$               endif
$!
$!
$               if key2b .eqs. "FILE"
$               then
$                  write sys$output ""
$                  write sys$output -
  "%CONFIG_H-I-NONPORT, ''key2' being asked for!"
$                  write sys$output -
 "-CONFIG_H-I-FILE_OLD, file.h will not be configured as is obsolete!"
$                  write sys$output -
 "-CONFIG_H_I-FCNTL_NEW, "Expecting fcntl.h to be configured instead!"
$                  write sys$output -
 "-CONFIG_H_I-FCNTL_CHK, "Unable to verify at this time!"
$                  write sys$output -
 "-CONFIG_H-I-REVIEW, Manual Code review required!"
$!
$                   if update_config_vms
$                   then
$                       open/append tfcv sys$disk:[]config_vms.h
$                       write tfcv ""
$                       write tfcv -
                "/* Check config.h for use of fcntl.h instead of file.h */"
$                       write tfcv ""
$                       close tfcv
$                   endif
$               endif
$!
$!              Now look it up in the DEC C RTL
$!---------------------------------------------
$               define/user sys$output nl:
$               define/user sys$error nl:
$               search/output=nl: 'dchfile' |'headf'|/exact
$               if '$severity' .eq. 1
$               then
$                   if key64 then write tf "#ifndef __VAX"
$                   write tf "#ifndef ''key2'"
$                   write tf "#define ''key2' 1"
$if p2 .nes. "" then write sys$output "''dchfile' - #define ''key2' 1"
$                   write tf "#endif"
$                   if key64 then write tf "#endif"
$set nover
$                   goto cfgh_in_loop1
$               endif
$!
$!
$!              Now look it up in the DEC C STARLET_C
$!---------------------------------------------
$               define/user sys$output nl:
$               define/user sys$error nl:
$               search/output=nl: 'starhfile' |'headf'|/exact
$               if '$severity' .eq. 1
$               then
$                   if key64 then write tf "#ifndef __VAX"
$                   write tf "#ifndef ''key2'"
$                   write tf "#define ''key2' 1"
$if p2 .nes. "" then write sys$output "''starfile' - #define ''key2' 1"
$                   write tf "#endif"
$                   if key64 then write tf "#endif"
$set nover
$                   goto cfgh_in_loop1
$               endif
$!
$!              Now look for OPENSSL headers
$!---------------------------------------------------------
$               if key2b .eqs. "OPENSSL"
$               then
$                   headf = headf - "OPENSSL_"
$                   header = f$search("''ssl_header_dir'''headf'.h")
$                   if header .nes. ""
$                   then
$                       write tf "#ifndef ''key2'"
$                       write tf "#define ''key2' 1"
$                       write tf "#endif"
$set nover
$                       goto cfgh_in_loop1
$                   endif
$               endif
$!
$!              Now look for Kerberos
$!------------------------------------------------------------
$               if key2b .eqs. "GSSAPI"
$               then
$                   header_dir = "sys$sysroot:[kerberos.include]"
$                   headf = headf - "GSSAPI_"
$                   header = f$search("''header_dir'''headf'.h")
$                   if header .nes. ""
$                   then
$                       write tf "#ifndef ''key2'"
$                       write tf "#define ''key2' 1"
$                       write tf "#endif"
$set nover
$                       goto cfgh_in_loop1
$                   endif
$               endif
$!
$set nover
$           else
$!
$!              Looking for a routine or a symbol
$!------------------------------------------------
$               if key2c .eqs. "MACRO"
$               then
$                   if (key2b .eqs. "FILE") .or. (key2b .eqs. "DATE") -
                        .or. (key2b .eqs. "LINE") .or. (key2b .eqs. "TIME")
$                   then
$                       write tf "#ifndef HAVE_''key2b'"
$                       write tf "#define HAVE_''key2b' 1"
$                       write tf "#endif"
$                   endif
$                   goto cfgh_in_loop1
$               endif
$!
$!              Special false tests
$!-------------------------------------
$               if double_under
$               then
$                   if key2b .eqs. "_FCNTL" .or. key2b .eqs. "__FCNTL"
$                   then
$                       write tf "/* #undef HAVE_''key2b' */"
$                       goto cfgh_in_loop1
$                   endif
$!
$                   if key2b .eqs. "_STAT" .or. key2b .eqs. "__STAT"
$                   then
$                       write tf "/* #undef HAVE_''key2b' */"
$                       goto cfgh_in_loop1
$                   endif
$!
$                   if key2b .eqs. "_READ" .or. key2b .eqs. "__READ"
$                   then
$                       write tf "/* #undef HAVE_''key2b' */"
$                       goto cfgh_in_loop1
$                   endif
$               endif
$!
$               keysym = key2b
$               if key2c .nes. "" then keysym = keysym + "_" + key2c
$               if key2d .nes. "" then keysym = keysym + "_" + key2d
$               if key2e .nes. "" then keysym = keysym + "_" + key2e
$!
$!
$!              Stat structure members
$!-------------------------------------
$               if key2b .eqs. "STRUCT"
$               then
$                   if key2c .eqs. "STAT" .and (key2d .nes. "")
$                   then
$                       key2b = key2b + "_" + key2c + "_" + key2d
$                       key2c = key2e
$                       key2d = ""
$                       key2e = ""
$                   endif
$               endif
$               if (key2b .eqs. "ST") .or. (key2b .eqs. "STRUCT_STAT_ST")
$               then
$                   keysym = "ST" + "_" + key2c
$                   keysym = f$edit(keysym,"LOWERCASE")
$               endif
$               if key2a .eqs. "STAT"
$               then
$                   if (f$locate("STATVFS", key2b) .eq. 0) .and. key2c .eqs. ""
$                   then
$                       keysym = f$edit(key2b, "LOWERCASE")
$                   endif
$!$                 if (key2b .eqs. "STATVFS" .or. key2b .eqs. "STATFS2" -
$!                      .or. key2b .eqs. "STATFS3") .and. key2c .nes. ""
$!
$                   if (key2b .eqs. "STATVFS") .and. key2c .nes. ""
$                   then
$!                      Should really verify that the structure
$!                      named by key2b actually exists first.
$!------------------------------------------------------------
$!
$!                      Statvfs structure members
$!-------------------------------------------------
$                       keysym = "f_" + f$edit(key2c,"LOWERCASE")
$                   endif
$               endif
$!
$!              UTMPX structure members
$!--------------------------------------
$               if key2b .eqs. "UT" .and. key2c .eqs. "UT"
$               then
$                   keysym = "ut_" + f$edit(key2d,"LOWERCASE")
$               endif
$!
$               if f$locate("MMAP",key2) .lt. key2_len
$               then
$                  write sys$output ""
$                  write sys$output -
  "%CONFIG_H-I-NONPORT, ''key2' being asked for!"
$                  write sys$output -
 "-CONFIG_H-I-MMAP, MMAP operations only work on STREAM and BINARY files!"
$                  write sys$output -
 "-CONFIG_H-I-REVIEW, Manual Code review required!"
$                   if update_config_vms
$                   then
$                       open/append tfcv sys$disk:[]config_vms.h
$                       write tfcv ""
$                       write tfcv -
                "/* Check config.h for use of ''key2' settings */"
$                       write tfcv ""
$                       close tfcv
$                   endif
$               endif
$!
$!
$               if keysym .eqs. "CRYPT"
$               then
$                  write sys$output ""
$                  write sys$output -
  "%CONFIG_H-I-NONPORT, ''key2' being asked for!"
$                  write sys$output -
 "-CONFIG_H-I-CRYPT, CRYPT operations on the VMS SYSUAF may not work!"
$                  write sys$output -
 "-CONFIG_H-I-REVIEW, Manual Code review required!"
$                   if update_config_vms
$                   then
$                       open/append tfcv sys$disk:[]config_vms.h
$                       write tfcv ""
$                       write tfcv -
                "/* Check config.h for use of ''keysym' */"
$                       write tfcv ""
$                       close tfcv
$                   endif
$               endif
$!
$!
$               if keysym .eqs. "EXECL"
$               then
$                  write sys$output ""
$                  write sys$output -
  "%CONFIG_H-I-NONPORT, ''key2' being asked for!"
$                  write sys$output -
 "-CONFIG_H-I-EXCEL, EXECL configured, Will probably not work."
$                  write sys$output -
 "-CONFIG_H-I-REVIEW, Manual Code review required!"
$                   if update_config_vms
$                   then
$                       open/append tfcv sys$disk:[]config_vms.h
$                       write tfcv ""
$                       write tfcv -
                "/* Check config.h for use of ''keysym' */"
$                       write tfcv ""
$                       close tfcv
$                   endif
$               endif
$!
$!
$!              Process if cpp supports ANSI-C stringizing '#' operator
$!-----------------------------------------------------------------------
$               if keysym .eqs. "STRINGIZE"
$               then
$                   write tf "#ifndef HAVE_STRINGIZE"
$                   write tf "#define HAVE_STRINGSIZE 1"
$                   write tf "#endif"
$                   goto cfgh_in_loop1
$               endif
$!
$               if keysym .eqs. "VOLATILE"
$               then
$                   write tf "#ifndef HAVE_VOLATILE"
$                   write tf "#define HAVE_VOLATILE 1"
$                   write tf "#endif"
$                   goto cfgh_in_loop1
$               endif
$!
$               if keysym .eqs. "ALLOCA"
$               then
$                   write tf "#ifndef HAVE_ALLOCA"
$                   write tf "#define HAVE_ALLOCA 1"
$                   write tf "#endif"
$                   goto cfgh_in_loop1
$               endif
$!
$               if keysym .eqs. "ERRNO_DECL"
$               then
$                   write tf "#ifndef HAVE_ERRNO_DECL"
$                   write tf "#define HAVE_ERRNO_DECL 1"
$                   write tf "#endif"
$                   goto cfgh_in_loop1
$               endif
$!
$               if keysym .eqs. "LONGLONG"
$               then
$                   write tf "#ifndef __VAX"
$                   write tf "#pragma message disable longlongtype"
$                   write tf "#ifndef HAVE_LONGLONG"
$                   write tf "#define HAVE_LONGLONG 1"
$                   write tf "#endif"
$                   write tf "#endif"
$                   goto cfgh_in_loop1
$               endif
$!
$!              May need to test compiler version
$!-----------------------------------------------
$               if keysym .eqs. "LONG_LONG"
$               then
$                   write tf "#ifndef __VAX"
$                   write tf "#pragma message disable longlongtype"
$                   write tf "#ifndef HAVE_LONG_LONG"
$                   write tf "#define HAVE_LONG_LONG 1"
$                   write tf "#endif"
$                   write tf "#endif"
$                   goto cfgh_in_loop1
$               endif
$!
$!              May need to test compiler version
$!-----------------------------------------------
$               if keysym .eqs. "UNSIGNED_LONG_LONG"
$               then
$                   write tf "#ifndef __VAX"
$                   write tf "#pragma message disable longlongtype"
$                   write tf "#ifndef HAVE_UNSIGNED_LONG_LONG"
$                   write tf "#define HAVE_UNSIGNED_LONG_LONG 1"
$                   write tf "#endif"
$                   write tf "#endif"
$                   goto cfgh_in_loop1
$               endif
$!
$!              May need to test compiler version
$!-----------------------------------------------
$               if keysym .eqs. "UNSIGNED_LONG_LONG_INT"
$               then
$                   write tf "#ifndef __VAX"
$                   write tf "#pragma message disable longlongtype"
$                   write tf "#ifndef HAVE_UNSIGNED_LONG_LONG_INT"
$                   write tf "#define HAVE_UNSIGNED_LONG_LONG_INT 1"
$                   write tf "#endif"
$                   write tf "#endif"
$                   goto cfgh_in_loop1
$               endif
$!
$!              May need to test compiler version
$!-----------------------------------------------
$               if keysym .eqs. "LONG_DOUBLE"
$               then
$                   write tf "#ifndef __VAX"
$                   write tf "#pragma message disable longlongtype"
$                   write tf "#ifndef HAVE_LONG_DOUBLE"
$                   write tf "#define HAVE_LONG_DOUBLE 1"
$                   write tf "#endif"
$                   write tf "#endif"
$                   goto cfgh_in_loop1
$               endif
$!
$               if keysym .eqs. "FCNTL_LOCK"
$               then
$                   write sys$output -
  "%CONFIG_H-I-NONPORT, ''key2' being asked for!
$                  write sys$output -
 "-CONFIG_H-I-REVIEW, Manual Code review required!"
$                   goto cfgh_in_loop1
$               endif
$!
$!
$!              These libraries are provided by the DEC C RTL
$!-------------------------------------------------------------
$               if keysym .eqs. "LIBINET" .or. keysym .eqs. "LIBSOCKET"
$               then
$                   write tf "#ifndef HAVE_''keysym'"
$                   write tf "#define HAVE_''keysym' 1"
$if p2 .nes. "" then write sys$output "''decc_shr' #define ''keysym' 1"
$                   write tf "#endif
$                   goto cfgh_in_loop1
$               endif
$!
$               if keysym .eqs. "HERRNO" then keysym = "h_errno"
$               if keysym .eqs. "UTIMBUF" then keysym = "utimbuf"
$               if key2c .eqs. "STRUCT"
$               then
$                   keysym = f$edit(key2d,"LOWERCASE")
$               else
$                   if key2_h .eqs. "_T"
$                   then
$                       if key2_t .eqs. "_TYPE"
$                       then
$                           keysym = f$extract(0, key2_len - 5, key2) - "HAVE_"
$                       endif
$                       keysym = f$edit(keysym,"LOWERCASE")
$                   endif
$               endif
$!
$!              Check the DEC C RTL shared image first
$!------------------------------------------------------
$               if f$search(tfile1) .nes. "" then delete 'tfile1';*
$               define/user sys$output nl:
$               define/user sys$error nl:
$               search/format=nonull/out='tfile1' 'decc_shr' 'keysym'
$               if '$severity' .eq. 1
$               then
$!
$!                  Not documented, but from observation
$!------------------------------------------------------
$                   define/user sys$output nl:
$                   define/user sys$error nl:
$                   if arch_type .eq. 3
$                   then
$                       keyterm = "''keysym'<SOH>"
$                   else
$                       if arch_type .eq. 2
$                       then
$                           keyterm = "''keysym'<BS>"
$                       else
$                           keyterm = "''keysym'<STX>"
$                       endif
$                   endif
$                   search/out=nl: 'tfile1' -
   "$''keyterm'","$g''keyterm'","$__utc_''keyterm'",-
   "$__utctz_''keyterm'","$__bsd44_''keyterm'","$bsd_''keyterm'",-
   "$''keysym'decc$","$G''keysym'decc$","$GX''keyterm'"
$                   severity = '$severity'
$!
$!
$!                  Of course the 64-bit stuff is different
$!---------------------------------------------------------
$                   if severity .ne. 1 .and. key64
$                   then
$                       define/user sys$output nl:
$                       define/user sys$error nl:
$                       search/out=nl: 'tfile1' "$_''keyterm'"
$!                      search/out 'tfile1' "$_''keyterm'"
$                       severity = '$severity'
$                   endif
$!
$!                  Unix compatibility routines
$!---------------------------------------------
$                   if severity .ne. 1
$                   then
$                       define/user sys$output nl:
$                       define/user sys$error nl:
$                       search/out=nl: 'tfile1' -
    "$__unix_''keyterm'","$__vms_''keyterm'","$_posix_''keyterm'"
$                       severity = '$severity'
$                   endif
$!
$!                  Show the result of the search
$!------------------------------------------------
$                   if 'severity' .eq. 1
$                   then
$                       if key64 then write tf "#ifndef __VAX"
$                       write tf "#ifndef ''key2'"
$                       write tf "#define ''key2' 1"
$if p2 .nes. "" then write sys$output "''decc_shr' #define ''key2' 1"
$                       write tf "#endif"
$                       if key64 then write tf "#endif"
$                       goto cfgh_in_loop1
$                   endif
$               endif
$               if f$search(tfile1) .nes. "" then delete 'tfile1';*
$!
$!              Check the DECC Header files next
$!----------------------------------------------
$               define/user sys$output nl:
$               define/user sys$error nl:
$               search/out=nl: 'decc_rtldef' -
                    "''keysym';", "''keysym'[", "struct ''keysym'"/exact
$               severity = '$severity'
$               if severity .eq. 1
$               then
$                   if key64 then write tf "#ifndef __VAX"
$                   write tf "#ifndef ''key2'"
$                   write tf "#define ''key2' 1"
$if p2 .nes. "" then write sys$output "''decc_rtldef' #define ''key2' 1"
$                   write tf "#endif"
$                   if key64 then write tf "#endif"
$                   goto cfgh_in_loop1
$               endif
$!
$!              Check kerberos
$!--------------------------------------------
$               if f$search("SYS$SYSROOT:[kerberos]include.dir") .nes. ""
$               then
$                   test_mit = "SYS$SYSROOT:[kerberos.include]gssapi_krb5.h"
$                   if (key2 .eqs. "HAVE_GSSAPI")
$                   then
$                       write tf "#ifndef ''key2'"
$                       write tf "#define ''key2' 1"
$                       write tf "#endif"
$                       goto cfgh_in_loop1
$                   endif
$               endif
$!
$           endif
$           write tf "/* ", xline, " */"
$           goto cfgh_in_loop1
$       endif
$!
$!
$!      Process SIZEOF directives found in SAMBA and others
$!----------------------------------------------------------
$       if key2a .eqs. "SIZEOF"
$       then
$           if key2b .eqs. "INO" .and. key2_h .eqs. "_T"
$           then
$               write tf "#ifndef SIZEOF_INO_T"
$               write tf "#if !__USING_STD_STAT
$               write tf "#define SIZEOF_INO_T 6"
$               write tf "#else
$               write tf "#define SIZEOF_INO_T 8"
$               write tf "#endif
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2b .eqs. "INTMAX" .and. key2_h .eqs. "_T"
$           then
$               write tf "#ifndef SIZEOF_INTMAX_T"
$               write tf "#ifdef __VAX"
$               write tf "#define SIZEOF_INTMAX_T 4"
$               write tf "#else"
$               write tf "#define SIZEOF_INTMAX_T 8"
$               write tf "#endif"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2b .eqs. "OFF" .and. key2_h .eqs. "_T"
$           then
$               write tf "#ifndef SIZEOF_OFF_T"
$               write tf "#if __USE_OFF64_T"
$               write tf "#define SIZEOF_OFF_T 8"
$               write tf "#else"
$               write tf "#define SIZEOF_OFF_T 4"
$               write tf "#endif"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2b .eqs. "CHAR" .and. key2_h .eqs. "_P"
$           then
$               write tf "#ifndef SIZEOF_CHAR_P"
$               write tf "#if __INITIAL_POINTER_SIZE == 64"
$               write tf "#define SIZEOF_CHAR_P 8"
$               write tf "#else"
$               write tf "#define SIZEOF_CHAR_P 4"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2b .eqs. "VOIDP"
$           then
$               write tf "#ifndef SIZEOF_VOIDP"
$               write tf "#if __INITIAL_POINTER_SIZE == 64"
$               write tf "#define SIZEOF_VOIDP 8"
$               write tf "#else"
$               write tf "#define SIZEOF_VOIDP 4"
$               write tf "#endif"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2b .eqs. "INT"
$           then
$               write tf "#ifndef SIZEOF_INT"
$               write tf "#define SIZEOF_INT 4"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2b .eqs. "SIZE" .and. key2_h .eqs. "_T"
$           then
$               write tf "#ifndef SIZEOF_SIZE_T"
$               write tf "#define SIZEOF_SIZE_T 4"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2b .eqs. "TIME" .and. key2_h .eqs. "_T"
$           then
$               write tf "#ifndef SIZEOF_TIME_T"
$               write tf "#define SIZEOF_TIME_T 4"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2b .eqs. "DOUBLE"
$           then
$               write tf "#ifndef SIZEOF_DOUBLE"
$               write tf "#define SIZEOF_DOUBLE 8"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2b .eqs. "LONG"
$           then
$               if key2c .eqs. ""
$               then
$                   write tf "#ifndef SIZEOF_LONG"
$                   write tf "#define SIZEOF_LONG 4"
$                   write tf "#endif"
$               else
$                   write tf "#ifndef SIZEOF_LONG_LONG"
$                   write tf "#ifndef __VAX"
$                   write tf "#define SIZEOF_LONG_LONG 8"
$                   write tf "#endif"
$                   write tf "#endif"
$               endif
$               goto cfgh_in_loop1
$           endif
$           write tf "/* ", xline, " */"
$           goto cfgh_in_loop1
$       endif
$!
$!      Process NEED directives
$!-------------------------------
$       if key2a .eqs. "NEED"
$       then
$           if key2b .eqs. "STRINGS" .and. key2_h .eqs. "_H"
$           then
$               write tf "#ifndef NEED_STRINGS_H"
$               write tf "#define NEED_STRINGS_H 1"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           write tf "/* ", xline, " */"
$           goto cfgh_in_loop1
$       endif
$!
$!      Process GETHOSTNAME directives
$!-------------------------------------
$       if key2 .eqs. "GETHOSTNAME_TYPE_ARG2"
$       then
$           write tf "#ifndef ''key2'"
$           write tf "#ifdef _DECC_V4_SOURCE"
$           write tf "#define ''key2' int"
$           write tf "#else"
$           write tf "#define ''key2' size_t"
$           write tf "#endif"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$!      Process GETNAMEINFO directives
$!-------------------------------------
$       if key2a .eqs. "GETNAMEINFO"
$       then
$           if key2 .eqs. "GETNAMEINFO_QUAL_ARG1"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' const"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2 .eqs. "GETNAMEINFO_TYPE_ARG1"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' struct sockaddr *"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2 .eqs. "GETNAMEINFO_TYPE_ARG2"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' size_t"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2 .eqs. "GETNAMEINFO_TYPE_ARG46"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' size_t"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2 .eqs. "GETNAMEINFO_TYPE_ARG7"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' int"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$       endif
$!
$!      Process RECV directives
$!-------------------------------------
$       if key2a .eqs. "RECV"
$       then
$           if key2 .eqs. "RECV_TYPE_ARG1"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' int"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2 .eqs. "RECV_TYPE_ARG2"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' void *"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2 .eqs. "RECV_TYPE_ARG3"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' size_t"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2 .eqs. "RECV_TYPE_ARG4"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' int"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2 .eqs. "RECV_TYPE_RETV"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' int"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$       endif
$!
$!      Process SEND directives
$!-------------------------------------
$       if key2a .eqs. "SEND"
$       then
$           if key2 .eqs. "SEND_QUAL_ARG2"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' const"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2 .eqs. "SEND_TYPE_ARG1"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' int"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2 .eqs. "SEND_TYPE_ARG2"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' void *"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2 .eqs. "SEND_TYPE_ARG3"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' size_t"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2 .eqs. "SEND_TYPE_ARG4"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' int"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$           if key2 .eqs. "SEND_TYPE_RETV"
$           then
$               write tf "#ifndef ''key2'"
$               write tf "#define ''key2' int"
$               write tf "#endif"
$               goto cfgh_in_loop1
$           endif
$       endif
$!
$!
$!      Process STATFS directives
$!-------------------------------
$!      if key2a .eqs. "STATFS"
$!      then
$!          write tf "/* ", xline, " */"
$!          goto cfgh_in_loop1
$!      endif
$!
$!      Process inline directive
$!------------------------------
$       if key2 .eqs. "inline"
$       then
$           write tf "#ifndef inline"
$           write tf "#define inline __inline"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$!      Process restrict directive
$!--------------------------------
$       if key2 .eqs. "restrict"
$       then
$           write tf "#ifndef restrict"
$           write tf "#define restrict __restrict"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$!      Process STDC_HEADERS (SAMBA!)
$!---------------------------
$       if key2 .eqs. "STDC_HEADERS"
$       then
$           write tf "#ifndef STDC_HEADERS"
$           write tf "#define STDC_HEADERS 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$!      Process PROTOTYPES directive
$!-------------------------------------
$       if key2 .eqs. "PROTOTYPES"
$       then
$           write tf "#ifndef PROTOTYPES"
$           write tf "#define PROTOTYPES 1"
$           write tf "#endif"
$           goto cfgh_in_loop1
$       endif
$!
$!      Special for SEEKDIR_RETURNS_VOID
$!---------------------------------------
$       if key2 .eqs. "SEEKDIR_RETURNS_VOID"
$       then
$           write tf "#ifndef SEEKDIR_RETURNS_VOID"
$           write tf "#define SEEKDIR_RETURNS_VOID 1"
$           write tf "#endif"
$       endif
$!
$!      Unknown - See if CONFIGURE can give a clue for this
$!----------------------------------------------------------
$       pflag = 0
$       set_flag = 0
$!      gproj_name = proj_name - "_VMS" - "-VMS"
$       if f$search(tfile1) .nes. "" then delete 'tfile1';*
$       define/user sys$output nl:
$       define/user sys$error nl:
$!      if f$locate("FILE", key2) .lt. key2_len then pflag = 1
$!      if f$locate("DIR", key2) .eq. key2_len - 3 then pflag = 1
$!      if f$locate("PATH", key2) .eq. key2_len - 4 then pflag = 1
$!
$       search/out='tfile1' 'configure_script' "''key2'="/exact
$       search_sev = '$severity'
$       if 'search_sev' .eq. 1
$       then
$           open/read/err=unknown_cf_rd_error sf 'tfile1'
$search_file_rd_loop:
$           read/end=unknown_cf_rd_err sf line_in
$           line_in = f$edit(line_in, "TRIM")
$           skey1 = f$element(0,"=",line_in)
$           if skey1 .eqs. key2
$           then
$               skey2 = f$element(1,"=",line_in)
$               skey2a = f$extract(0,2,skey2)
$!
$!
$!              We can not handle assignment to shell symbols.
$!              For now skip them.
$!------------------------------------------------------------
$               if f$locate("$", skey2) .lt. f$length(skey2)
$               then
$                   write tf "/* ", xline, " */"
$                   set_flag = 1
$                   goto found_in_configure
$               endif
$!
$!              Keep these two cases separate to make it easier to add
$!              more future intelligence to this routine
$!----------------------------------------------------------------------
$               if skey2a .eqs. """`"
$               then
$!                  if pflag .eq. 1
$!                  then
$!                      write tf "#ifndef ''key2'"
$!                      write tf "#define ",key2," """,gproj_name,"_",key2,""""
$!                      write tf "#endif"
$!                  else
$!                      Ignore this for now
$!------------------------------------------
$                       write tf "/* ", xline, " */"
$!                  endif
$                   set_flag = 1
$                   goto found_in_configure
$               endif
$               if skey2a .eqs. """$"
$               then
$!                  if pflag .eq. 1
$!                  then
$!                      write tf "#ifndef ''key2'"
$!                      write tf "#define ",key2," """,gproj_name,"_",key2,""""
$!                      write tf "#endif"
$!                  else
$!                      Ignore this for now
$!-------------------------------------------
$                       write tf "/* ", xline, " */"
$!                  endif
$                   set_flag = 1
$                   goto found_in_configure
$               endif
$!
$!              Remove multiple layers of quotes if present
$!----------------------------------------------------------
$               if f$extract(0, 1, skey2) .eqs. "'"
$               then
$                   skey2 = skey2 - "'" - "'" - "'" - "'"
$               endif
$               if f$extract(0, 1, skey2) .eqs. """"
$               then
$                   skey2 = skey2 - """" - """" - """" - """"
$               endif
$               write tf "#ifndef ''key2'"
$               if skey2 .eqs. ""
$               then
$                   write tf "#define ",key2
$               else
$!                  Only quote non-numbers
$!----------------------------------------
$                   if f$string(skey2+0) .eqs. skey2
$                   then
$                       write tf "#define ",key2," ",skey2
$                   else
$                       write tf "#define ",key2," """,skey2,""""
$                   endif
$               endif
$               write tf "#endif"
$               set_flag = 1
$           else
$               goto search_file_rd_loop
$!              if pflag .eq. 1
$!              then
$!                  write tf "#ifndef ''key2'"
$!                  write tf "#define ",key2," """,gproj_name,"_",key2,""""
$!                  write tf "#endif"
$!                  set_flag = 1
$!              endif
$           endif
$found_in_configure:
$unknown_cf_rd_err:
$           if f$trnlnm("sf","lnm$process",,"SUPERVISOR") .nes. ""
$           then
$               close sf
$           endif
$           if f$search(tfile1) .nes. "" then delete 'tfile1';*
$           if set_flag .eq. 1 then goto cfgh_in_loop1
$       endif
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
$!
$!
$! Write out the tail
$!--------------------
$write_tail:
$gosub write_config_h_tail
$!
$! Exit and clean up
$!--------------------
$general_error:
$status = '$status'
$all_exit:
$set noon
$if f$trnlnm("sf","lnm$process",,"SUPERVISOR") .nes. "" then close sf
$if f$trnlnm("tf","lnm$process",,"SUPERVISOR") .nes. "" then close tf
$if f$trnlnm("inf","lnm$process",,"SUPERVISOR") .nes. "" then close inf
$if f$trnlnm("tf1","lnm$process",,"SUPERVISOR") .nes. "" then close tf1
$if f$trnlnm("tf2","lnm$process",,"SUPERVISOR") .nes. "" then close tf2
$if f$trnlnm("tfcv","lnm$process",,"SUPERVISOR") .nes. "" then close tfcv
$if f$type(tfile1) .eqs. "STRING"
$then
$   if f$search(tfile1) .nes. "" then delete 'tfile1';*
$endif
$if f$type(dchfile) .eqs. "STRING"
$then
$   if f$search(dchfile) .nes. "" then delete 'dchfile';*
$endif
$if f$type(starhfile) .eqs. "STRING"
$then
$   if f$search(starhfile) .nes. "" then delete 'starhfile';*
$endif
$if f$type(configure_script) .eqs. "STRING"
$then
$   if f$search(configure_script) .nes. "" then delete 'configure_script';*
$endif
$exit 'status'
$!
$!
$control_y:
$   status = ss_control_y
$   goto all_exit
$!
$!
$!
$! Gosub to write a new config_vms.h
$!-----------------------------------
$write_config_vms:
$outfile = "sys$disk:[]config_vms.h"
$create 'outfile'
$open/append tf 'outfile'
$write tf "/* File: config_vms.h"
$write tf "**"
$write tf "** This file contains the manual edits needed for porting"
$!write tf "** the ''proj_name' package to OpenVMS.
$write tf "**"
$write tf "** Edit this file as needed.  The procedure that automatically"
$write tf "** generated this header stub will not overwrite or make any"
$write tf "** changes to this file."
$write tf "**"
$write tf -
 "** ", datetime, tab, username, tab, "Generated by ''my_proc_file'"
$write tf "**"
$write tf -
 "**========================================================================*/"
$write tf ""
$close tf
$return
$!
$! gosub to write out a documentation header for config.h
$!----------------------------------------------------------------
$write_config_h_header:
$outfile = "sys$disk:[]config.h"
$create 'outfile'
$open/append tf 'outfile'
$write tf "#ifndef CONFIG_H"
$write tf "#define CONFIG_H"
$write tf "/* File: config.h"
$write tf "**"
$write tf -
  "** This file contains the options needed for porting "
$write tf "** the project on a VMS system."
$write tf "**"
$write tf "** Try not to make any edits to this file, as it is"
$write tf "** automagically generated."
$write tf "**"
$write tf "** Manual edits should be made to the config_vms.h file."
$write tf "**"
$write tf -
 "** ", datetime, tab, username, tab, "Generated by ''my_proc_file'"
$write tf "**"
$write tf -
 "**========================================================================*/"
$write tf ""
$write tf "#if (__CRTL_VER >= 70200000) && !defined (__VAX)"
$write tf "#define _LARGEFILE 1"
$write tf "#endif"
$write tf ""
$write tf "#ifndef __VAX"
$write tf "#ifdef __CRTL_VER"
$write tf "#if __CRTL_VER >= 80200000"
$write tf "#define _USE_STD_STAT 1"
$write tf "#endif"
$write tf "#endif"
$write tf "#endif"
$write tf ""
$!
$write tf " /* Allow compiler builtins */"
$write tf "/*-------------------------*/"
$write tf "#ifdef __DECC_VER"
$write tf "#include <non_existent_dir:builtins.h>"
$write tf "#endif"
$!
$write tf ""
$return
$!
$! gosub to write out the tail for config.h and close it
$!---------------------------------------------------------
$write_config_h_tail:
$write tf ""
$write tf " /* Include the hand customized settings */"
$write tf "/*--------------------------------------*/"
$write tf "#include ""config_vms.h"""
$write tf ""
$write tf "#endif /* CONFIG_H */"
$close tf
$return
$!
