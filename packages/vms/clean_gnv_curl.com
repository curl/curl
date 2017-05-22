$! File: clean_gnv_curl.COM
$!
$! $Id$
$!
$! The GNV environment leaves behind some during the configure and build
$! procedure that need to be cleaned up.
$!
$! The default is to remove all the left over stuff from running the
$! configure script and to remove all intermediate binary files.
$!
$! This should be run with no parameters after the gnv_curl_configure.sh
$! script is run.
$!
$! Parameter P1: REALCLEAN
$!   This removes all build products and brings the environment back to
$!   the point where the gnv_curl_configure.sh procedure needs to be run again.
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
$!
$! 07-Jul-2009	J. Malmberg
$!============================================================================
$!
$! Save this so we can get back.
$ default_dir = f$environment("default")
$!
$!
$! Move to where the base directory is.
$ set def [--]
$!
$!
$ file = "sys$login:sh*."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "sys$login:make*."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[]confdefs.h"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[]conftest.dsf"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[]conftest.lis"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[]conftest.sym"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$!
$ file = "lcl_root:[.conf*...]*.*"
$ if f$search(file) .nes. "" then delete 'file';*
$ file = "lcl_root:[]conf*.dir
$ if f$search(file) .nes. "" then delete 'file';*
$!
$!
$ file = "lcl_root:[.lib]*.out"
$ if f$search(file) .nes. "" then delete 'file';*
$ file = "lcl_root:[.lib]*.o"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$!
$ file = "lcl_root:[.lib]*.lis"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.src]*.lis"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.src]cc_temp*."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.src]*.dsf"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.src]*.o"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.lib]ar*."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.lib]cc_temp*."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[...]*.lo"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[...]*.a"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[...]*.la"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[...]*.lai"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.packages.vms]curl-*_original_src.bck"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.packages.vms]curl_d-*_original_src.bck"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.packages.vms]curl-*_vms_src.bck"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.packages.vms]curl_d-*_vms_src.bck"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.packages.vms]curl-*.release_notes"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.packages.vms]curl_d-*.release_notes"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.packages.vms]*-curl-*.pcsi$desc"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.packages.vms]*-curl_d-*.pcsi$desc"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.packages.vms]*-curl-*.pcsi$text"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.packages.vms]*-curl_d-*.pcsi$text"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$!======================================================================
$!
$ if p1 .nes. "REALCLEAN" then goto all_exit
$!
$ file = "lcl_root:[...]*.obj"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[...]Makefile."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[...]libtool."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[...]*.lis"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[...]POTFILES."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[]libcurl.pc"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[]curl-config."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[]config.h"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.src]config.h"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.src]curl."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.tests]configurehelp.pm"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.lib]config.h"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.lib]curl_config.h"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.lib]libcurl.vers"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[]ca-bundle.h"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[]config.log"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[]config.status"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[]conftest.dangle"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[]CXX$DEMANGLER_DB."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[]stamp-h1."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[...]stamp-h1."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[...]stamp-h2."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[...]stamp-h3."
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.lib]*.a"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[...]*.spec"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[...]gnv$*.*"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[...]gnv*.opt"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.packages.EPM]curl.list"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.packages.vms]macro32_exactcase.exe"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.packages.vms]report_openssl_version.exe"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.packages.vms]hp_ssl_release_info.txt"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$ file = "lcl_root:[.src]curl.exe"
$ if f$search(file) .nes. "" then delete 'file';*
$!
$all_exit:
$!
$! Put the default back.
$!-----------------------
$ set def 'default_dir'
$!
$ exit
