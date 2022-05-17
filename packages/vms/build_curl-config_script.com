$! build_curl-config_script.com
$!
$! This generates the curl-config. script from the curl-config.in file.
$!
$! Copyright 2014 - 2022, John Malmberg
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
$! 16-Dec-2014	J. Malmberg
$!
$!===========================================================================
$!
$! Skip this if the curl-config. already exists.
$ if f$search("[--]curl-config.") .nes. "" then goto all_exit
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
$ x_prefix = "/usr"
$ x_exec_prefix = "/usr"
$ x_includedir = "${prefix}/include"
$ x_cppflag_curl_staticlib = "-DCURL_STATICLIB"
$ x_enabled_shared = "no"
$ x_curl_ca_bundle = ""
$ x_cc = "cc"
$ x_support_features = "SSL IPv6 libz NTLM"
$ x_support_protocols1 = "DICT FILE FTP FTPS GOPHER HTTP HTTPS IMAP IMAPS LDAP"
$ x_support_protocols2 = " LDAPS POP3 POP3S RTSP SMTP SMTPS TELNET TFTP"
$ x_support_protocols = x_support_protocols1 + x_support_protocols2
$ x_curlversion = "0.0.0.0"
$ x_versionnum = ""
$ x_libdir = "${prefix}/lib"
$ x_require_lib_deps = ""
$ x_enable_static = ""
$ x_ldflags = ""
$ part1 = "-L/usr/lib -L/SSL_LIB -lssl -lcrypto -lz"
$ if arch_name .eqs. "VAX"
$ then
$   x_libcurl_libs = part1
$ else
$   x_libcurl_libs = part1 + " -lgssapi"
$ endif
$ x_libext = "a"
$!
$! Get the version number
$!-----------------------
$ i = 0
$ open/read/error=version_loop_end vhf [--.include.curl]curlver.h
$ version_loop:
$   read/end=version_loop_end vhf line_in
$   if line_in .eqs. "" then goto version_loop
$   if f$locate("#define LIBCURL_VERSION ", line_in) .eq. 0
$   then
$       x_curlversion = f$element(2," ", line_in) - """" - """"
$       i = i + 1
$   endif
$   if f$locate("#define LIBCURL_VERSION_NUM ", line_in) .eq. 0
$   then
$       x_versionnum = f$element(2," ", line_in) - """" - """"
$       i = i + 1
$   endif
$   if i .lt 2 then goto version_loop
$ version_loop_end:
$ close vhf
$!
$ kit_type = "V"
$ if f$locate("-", x_curlversion) .lt. f$length(x_curlversion)
$ then
$   kit_type = "D"
$   x_prefix = "/beta"
$   x_exec_prefix = "/beta"
$ endif
$!
$ if kit_type .nes. "D"
$ then
$    part1 = "        echo "" '--prefix=/usr' '--exec-prefix=/usr' "
$ else
$    part1 = "        echo "" '--prefix=/beta' '--exec_prefix=/beta' "
$ endif
$ if arch_name .eqs. "VAX"
$ then
$    part3 = ""
$ else
$    part3 = "'--with-gssapi' "
$ endif
$ part2 = "'--disable-dependency-tracking' '--disable-libtool-lock' "
$ part4 = "'--disable-ntlm-wb' '--with-ca-path=gnv$curl_ca_path'"""
$!
$ x_configure_options = part1 + part2 + part3 + part4
$!
$!
$ open/read/error=read_loop_end c_c_in sys$disk:[--]curl-config.in
$ create sys$disk:[--]curl-config.
$ open/append c_c_out sys$disk:[--]curl-config.
$read_loop:
$   read/end=read_loop_end c_c_in line_in
$   line_in_len = f$length(line_in)
$   if f$locate("@", line_in) .ge. line_in_len
$   then
$       write c_c_out line_in
$       goto read_loop
$   endif
$   i = 0
$   line_out = ""
$sub_loop:
$       ! Replace between pairs of @ by alternating the elements.
$       ! If mis-matched pairs, do not substitute anything.
$       section1 = f$element(i, "@", line_in)
$       if section1 .eqs. "@"
$       then
$           goto sub_loop_end
$       endif
$       i = i + 1
$       section2 = f$element(i, "@", line_in)
$       if section2 .eqs. "@"
$       then
$           goto sub_loop_end
$       endif
$       i = i + 1
$       section3 = f$element(i, "@", line_in)
$       if section3 .eqs. "@"
$       then
$           if line_out .eqs. "" then line_out = line_in
$           goto sub_loop_end
$       endif
$       line_out = line_out + section1
$       if f$type(x_'section2') .eqs. "STRING"
$       then
$           line_out = line_out + x_'section2'
$       endif
$       goto sub_loop
$sub_loop_end:
$   write c_c_out line_out
$   goto read_loop
$read_loop_end:
$ close c_c_in
$ close c_c_out
