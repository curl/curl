$! File: generate_vax_transfer.com
$!
$! File to generate and compile the VAX transfer vectors from reading in the
$! Alpha/Itanium gnv_libcurl_symbols.opt file.
$!
$! This procedure patches the VAX Macro32 assembler to be case sensitive
$! and then compiles the generated
$!
$! The output of this procedure is:
$!     gnv_libcurl_xfer.mar_exact
$!     gnv_libcurl_xfer.obj
$!     gnv_libcurl_xfer.opt
$!     macro32_exactcase.exe
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
$! Save this so we can get back.
$ default_dir = f$environment("default")
$!
$ on warning then goto all_exit
$!
$! Want hard tabs in the generated file.
$ tab[0,8] = 9
$!
$! This procedure is used on VAX only
$ if (f$getsyi("HW_MODEL") .ge. 1024)
$ then
$   write sys$output "This procedure is only used on VAX."
$   goto all_exit
$ endif
$!
$!
$! Get the libcurl version to generate the ident string.
$! ident string is max of 31 characters.
$!
$ ident_string = "unknown"
$ open/read cver [-.-.include.curl]curlver.h
$cver_loop:
$ read/end=cver_loop_end cver line_in
$ line_in = f$edit(line_in, "COMPRESS,TRIM")
$ if line_in .eqs. "" then goto cver_loop
$ code = f$extract(0, 1, line_in)
$ if code .nes. "#" then goto cver_loop
$ directive = f$element(0, " ", line_in)
$ if directive .nes. "#define" then goto cver_loop
$ name = f$element(1, " ", line_in)
$ if name .nes. "LIBCURL_VERSION" then goto cver_loop
$ ident_string = f$element(2, " ", line_in) - "" - ""
$cver_loop_end:
$ close cver
$!
$ open/read aopt gnv_libcurl_symbols.opt
$!
$! Write out the header
$ gosub do_header
$!
$ open/append vopt gnv_libcurl_xfer.mar_exact
$ write vopt tab,".IDENT /", ident_string, "/"
$!
$ write vopt tab, ".PSECT LIBCURL_XFERVECTORS  -"
$ write vopt tab,tab,tab, "PIC,USR,CON,REL,GBL,SHR,EXE,RD,NOWRT,QUAD"
$ write vopt ""
$ write vopt tab, "SPARE", tab, "; never delete this spare"
$ write vopt ";"
$ write vopt ";", tab, "Exact case and upper case transfer vectors"
$!
$ alias_count = 0
$vector_loop:
$!
$!  Read in symbol_vector
$!
$   read/end=vector_loop_end aopt line_in
$   line = f$edit(line_in, "UNCOMMENT,COMPRESS,TRIM")
$   if line .eqs. "" then goto vector_loop
$!
$   line_u = f$edit(line, "UPCASE")
$   key = f$element(0, "=", line_u)
$   if (key .eqs. "SYMBOL_VECTOR")
$   then
$       symbol_string = f$element(1, "=", line) - "("
$       symbol_type = f$element(2, "=", line_u) - ")"
$       symbol_name = f$element(1, "/", symbol_string)
$       if symbol_type .nes. "PROCEDURE"
$       then
$           write sys$output "%CURLBUILD-W-NOTPROC, " + -
$                            "This procedure can only handle procedure vectors"
$           write sys$output -
"Data vectors require manual construction for which this procedure or"
$           write sys$output -
"the shared library needs to be updated to resolve."
$           write sys$output -
"the preferred solution is to have a procedure return the address of the "
$           write sys$output -
"the variable instead of having a variable, as if the size of the variable "
            write sys$output -
"changes, the symbol vector is no longer backwards compatible."
$       endif
$       if (symbol_name .eqs. "/")
$       then
$           symbol_name = symbol_string
$           write vopt tab, symbol_type, tab, symbol_name
$       else
$           alias_count = alias_count + 1
$           symbol_alias = f$element(0, "/", symbol_string)
$           write vopt -
                  tab, "''symbol_type_U", tab, symbol_name, tab, symbol_alias
$       endif
$   endif
$   goto vector_loop
$vector_loop_end:
$!
$! End of pass one, second pass needed if aliases exist
$ close aopt
$!
$ if alias_count .eq. 0 then goto finish_file
$!
$! Start pass 2, write stub routine header
$!
$ open/read aopt gnv_libcurl_symbols.opt
$!
$alias_loop:
$!
$!  Read in symbol_vector
$!
$   read/end=alias_loop_end aopt line_in
$   line = f$edit(line_in, "UNCOMMENT,COMPRESS,TRIM")
$   if line .eqs. "" then goto alias_loop
$!
$   line_u = f$edit(line, "UPCASE")
$   key = f$element(0, "=", line_u)
$   if (key .eqs. "SYMBOL_VECTOR")
$   then
$       symbol_string = f$element(1, "=", line) - "("
$       symbol_type = f$element(2, "=", line_u) - ")"
$       symbol_name = f$element(1, "/", symbol_string)
$       if (symbol_name .eqs. "/")
$       then
$           symbol_name = symbol_string
$       else
$           alias_count = alias_count + 1
$           symbol_alias = f$element(0, "/", symbol_string)
$           write vopt tab, ".ENTRY", tab, symbol_alias, ", ^M<>"
$       endif
$   endif
$   goto alias_loop
$! read in symbol_vector
$! if not alias, then loop
$! write out subroutine name
$!
$alias_loop_end:
$!
$ write vopt tab, "MOVL #1, R0"
$ write vopt tab, "RET"
$!
$finish_file:
$!
$ write vopt ""
$ write vopt tab, ".END"
$!
$ close aopt
$ close vopt
$!
$! Patch the Macro32 compiler
$!----------------------------
$ patched_macro = "sys$disk:[]macro32_exactcase.exe"
$ if f$search(patched_macro) .eqs. ""
$ then
$   copy sys$system:macro32.exe 'patched_macro'
$   patch @macro32_exactcase.patch
$ endif
$ define/user macro32 'patched_macro'
$ macro/object=gnv_libcurl_xfer.obj gnv_libcurl_xfer.mar_exact
$!
$! Create the option file for linking the shared image.
$ create gnv_libcurl_xfer.opt
$ open/append lco gnv_libcurl_xfer.opt
$ write lco "gsmatch=lequal,1,1"
$ write lco "cluster=transfer_vector,,,''default_dir'gnv_libcurl_xfer"
$ write lco "collect=libcurl_global, libcurl_xfervectors"
$ close lco
$!
$!
$ goto all_exit
$!
$! Process the header
$do_header:
$!
$! Force the mode of the file to same as text editor generated.
$ create gnv_libcurl_xfer.mar_exact
$deck
; File: gnv_libcurl_xfer.mar_exact
;
; VAX transfer vectors
;
; This needs to be compiled with a specialized patch on Macro32 to make it
; preserve the case of symbols instead of converting it to uppercase.
;
; This patched Macro32 requires all directives to be in upper case.
;
; There are three sets of symbols for transfer vectors here.
;
; The first for upper case which matches the tradition method of generating
; VAX transfer vectors.
;
; The second is the exact case for compatibility with open source C programs
; that expect exact case symbols in images.  These are separated because a
; previous kit had only upper case symbols.
;
; The third is the routine stub that is used to resolve part of the upper
; case transfer vectors, with exact case entry symbols.
;
; When you add routines, you need to add them after the second set of transfer
; vectors for both upper and exact case, and then additional entry points
; in upper case added to stub routines.
;
;*************************************************************************

        .TITLE libcurl_xfer - Transfer vector for libcurl
        .DISABLE GLOBAL

;
; Macro to generate a transfer vector entry
;
        .MACRO  PROCEDURE       NAME
        .EXTRN          'NAME
        .ALIGN  QUAD
        .TRANSFER       'NAME
        .MASK           'NAME
        JMP             'NAME+2
        .ENDM

        .MACRO  PROCEDUREU      NAME    NAMEU
        .EXTRN          'NAME
        .ALIGN  QUAD
        .TRANSFER       'NAMEU
        .MASK           'NAME
        JMP             'NAME+2

        .ENDM
;
;
; Macro to reserve a spare entry.
;
        .MACRO  SPARE
        .ALIGN QUAD
        .ALIGN QUAD
        .QUAD   0
        .ENDM

$EOD
$!
$!
$ return
$!
$all_exit:
$set def 'default_dir'
$exit '$status'
