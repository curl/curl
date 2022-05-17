$! File: build_libcurl_pc.com
$!
$! $Id:$
$!
$! Build the libcurl.pc file from the libcurl.pc.in file
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
$! 15-Jun-2013  J. Malmberg
$!
$!===========================================================================
$!
$! Skip this if the libcurl.pc already exists.
$ if f$search("[--]libcurl.pc") .nes. "" then goto all_exit
$!
$! Need to know the kit type.
$ kit_name = f$trnlnm("GNV_PCSI_KITNAME")
$ if kit_name .eqs. ""
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
$ pc_file_in = "[--]libcurl^.pc.in"
$!
$ if f$search(pc_file_in) .eqs. ""
$ then
$    pc_file_in = "[--]libcurl.pc$5nin"
$    if f$search(pc_file_in) .eqs. ""
$    then
$        pc_file_in = "[--]libcurl.pc_in"
$        if f$search(pc_file_in) .eqs. ""
$        then
$            write sys$output "Can not find libcurl.pc.in."
$            goto all_exit
$        endif
$    endif
$ endif
$!
$ if (f$getsyi("HW_MODEL") .lt. 1024)
$ then
$    arch_name = "VAX"
$ else
$    arch_name = ""
$    arch_name = arch_name + f$edit(f$getsyi("ARCH_NAME"), "UPCASE")
$    if (arch_name .eqs. "") then arch_name = "UNK"
$ endif
$!
$!
$ curl_version = "0.0.0"
$ open/read vf [--.src]tool_version.h
$version_loop:
$   read vf/end=version_loop_end line_in
$   if line_in .eqs. "" then goto version_loop
$   key = f$element(0, " ", line_in)
$   if key .nes. "#define" then goto version_loop
$   name = f$element(1, " ", line_in)
$   if name .eqs. "VERSION"
$   then
$       curl_version = f$element(2, " ", line_in) - """" - """"
$   else
$       goto version_loop
$   endif
$version_loop_end:
$ close vf
$!
$!
$ create [--]libcurl.pc
$ open/append pco [--]libcurl.pc
$ open/read pci 'pc_file_in'
$pc_file_loop:
$ read pci/end=pc_file_loop_end line_in
$!
$! blank lines
$ if line_in .eqs. ""
$ then
$   write pco ""
$   goto pc_file_loop
$ endif
$!
$! comment lines
$ key = f$extract(0, 1, line_in)
$ if key .eqs. "#"
$ then
$   write pco line_in
$   goto pc_file_loop
$ endif
$!
$! Special handling for libs.
$ if f$locate("Libs:", line_in) .eq. 0
$ then
$   write pco "#",line_in
$   goto pc_file_loop
$ endif
$! No substitution line
$ line_in_len = f$length(line_in)
$ if f$locate("@", line_in) .ge. line_in_len
$ then
$   write pco line_in
$   goto pc_file_loop
$ endif
$!
$ if f$locate("@prefix@", line_in) .lt line_in_len
$ then
$    if kit_type .nes. "D"
$    then
$        write pco "prefix=/usr"
$    else
$        write pco "prefix=/beta"
$    endif
$    goto pc_file_loop
$ endif
$ if f$locate("@exec_prefix@", line_in) .lt line_in_len
$ then
$    if kit_type .nes. "D"
$    then
$        write pco "exec_prefix=/usr"
$    else
$        write pco "exec_prefix=/beta"
$    endif
$    goto pc_file_loop
$ endif
$ if f$locate("@libdir@", line_in) .lt line_in_len
$ then
$    write pco "libdir=$(exec_prefix}/lib"
$    goto pc_file_loop
$ endif
$ if f$locate("@includedir@", line_in) .lt line_in_len
$ then
$    write pco "includedir=$(prefix}/include"
$    goto pc_file_loop
$ endif
$ if f$locate("@SUPPORT_PROTOCOLS@", line_in) .lt line_in_len
$ then
$    proto1 = "DICT FILE FTP FTPS GOPHER HTTP HTTPS IMAP IMAPS"
$    proto2 = " LDAP LDAPS POP3 POP3S RTSP SMTP SMTPS TELNET TFTP"
$    proto = proto1 + proto2
$    write pco "supported_protocols=""" + proto + """"
$    goto pc_file_loop
$ endif
$ if f$locate("@SUPPORT_FEATURES@", line_in) .lt line_in_len
$ then
$    if arch_name .eqs. "VAX"
$    then
$        write pco "supported_features=""SSL libz NTLM"""
$    else
$        write pco "supported_features=""SSL IPv6 libz NTLM"""
$    endif
$    goto pc_file_loop
$ endif
$ if f$locate("@CURLVERSION@", line_in) .lt line_in_len
$ then
$    write pco "Version: ''curl_version'"
$    goto pc_file_loop
$ endif
$ if f$locate("@LIBCURL_LIBS@", line_in) .lt line_in_len
$ then
$    if arch_name .eqs. "VAX"
$    then
$        write pco "Libs.private: -lssl -lcrypto -lz"
$    else
$        write pco "Libs.private: -lssl -lcrypto -lgssapi -lz"
$    endif
$    goto pc_file_loop
$ endif
$ if f$locate("@CPPFLAG_CURL_STATICLIB@", line_in) .lt line_in_len
$ then
$    write pco "Cflags: -I${includedir} -DCURL_STATICLIB"
$    goto pc_file_loop
$ endif
$!
$pc_file_loop_end:
$ close pco
$ close pci
$!
$all_exit:
$ exit
