$! File: curl_Startup.com
$!
$! $Id$
$!
$! Procedure to setup the CURL libraries for use by programs from the
$! VMS SYSTARTUP*.COM procedure.
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
$! 15-Jun-2009 J. Malmberg
$! 30-Jul-2013 J. Malmberg  Update for Curl 7.32
$!========================================================================
$!
$!
$! GNV$GNU if needed.
$ if f$trnlnm("GNV$GNU") .eqs. ""
$ then
$   x = f$trnlnm("GNU","LNM$SYSTEM_TABLE")
$   if x .eqs. ""
$   then
$       write sys$output "GNV must be started up before this procedure.
$       exit 44
$   endif
$   define/system/exec/trans=conc GNV$GNU 'x'
$ endif
$!
$!
$ myproc = f$environment("procedure")
$!
$! ZLIB needed.
$ if f$trnlnm("GNV$LIBZSHR32") .eqs. ""
$ then
$   zlib_startup = f$parse("gnv$zlib_startup.com;0", myproc,,,)
$   if f$search(zlib_startup) .nes. ""
$   then
$       @'zlib_startup
$   else
$       write sys$output "ZLIB package not found and is required."
$       exit 44
$   endif
$ endif
$!
$!
$ curl_ssl_libcrypto32 = ""
$ curl_ssl_libssl32 = ""
$ gnv_ssl_libcrypto32 = "gnv$gnu:[lib]ssl$libcrypto_shr32.exe"
$ gnv_ssl_libssl32 = "gnv$gnu:[lib]ssl$libssl_shr32.exe"
$ if f$search(gnv_ssl_libcrypto32) .nes. ""
$ then
$   curl_ssl_libcrypto32 = gnv_ssl_libcrypto32
$   curl_ssl_libssl32 = gnv_ssl_libssl32
$ else
$   hp_ssl_libcrypto32 = "sys$share:ssl$libcrypto_shr32.exe"
$   hp_ssl_libssl32 = "sys$share:ssl$libssl_shr32.exe"
$   if f$search(hp_ssl_libcrypto32) .nes. ""
$   then
$       curl_ssl_libcrypto32 = hp_ssl_libcrypto32
$       curl_ssl_libssl32 = hp_ssl_libssl32
$   else
$       write sys$output "HP SSL package not found and is required."
$   endif
$ endif
$!
$ define/system/exec gnv$curl_ssl_libcryptoshr32 'curl_ssl_libcrypto32'
$ define/system/exec gnv$curl_ssl_libsslshr32 'curl_ssl_libssl32'
$!
$!
$! CURL setup
$ define/system/exec gnv$libcurl gnv$gnu:[usr.lib]GNV$LIBCURL.EXE
$ define/system/exec gnv$curl_include gnv$gnu:[usr.include.curl]
$ if .not. f$file_attributes("gnv$libcurl", "known")
$ then
$   install ADD gnv$libcurl/OPEN/SHARE/HEADER
$ else
$   install REPLACE gnv$libcurl/OPEN/SHARE/HEADER
$ endif
$!
$!
$ curl_exe = "gnv$gnu:[usr.bin]gnv$curl.exe"
$ if .not. f$file_attributes(curl_exe, "known")
$ then
$   install ADD 'curl_exe'/OPEN/SHARE/HEADER
$ else
$   install REPLACE 'curl_exe'/OPEN/SHARE/HEADER
$ endif
$!
$all_exit:
$ exit
