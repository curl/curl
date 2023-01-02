$! File: setup_gnv_curl_build.com
$!
$! Set up build environment for building Curl under GNV on VMS.
$!
$! GNV needs some files moved into the other directories to help with
$! the configure script and the build.
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
$!=======================================================================
$!
$! Save this so we can get back.
$ default_dir = f$environment("default")
$!
$! Move to where the Configure script is.
$ set def [--]
$!
$! Get the path to where the Configure script is.
$ base_dir = f$environment("default")
$!
$! Allow arguments to be grouped together with comma or separated by spaces
$! Do no know if we will need more than 8.
$ args = "," + p1 + "," + p2 + "," + p3 + "," + p4 + ","
$ args = args + p5 + "," + p6 + "," + p7 + "," + p8 + ","
$!
$! Provide lower case version to simplify parsing.
$ args_lower = f$edit(args, "LOWERCASE,COLLAPSE")
$!
$ args_len = f$length(args)
$ args_lower_len = f$length(args_lower)
$!
$ tests = 0
$ if f$locate(",test", args_lower) .lt. args_lower_len
$ then
$   tests = 1
$ endif
$!
$ examples = 0
$ if f$locate(",exam", args_lower) .lt. args_lower_len
$ then
$   examples = 1
$ endif
$!
$! We want detailed build logs.
$ clist = "/list/show=(expan,includ)"
$!
$! We want full symbol names in exact case.  Need a common
$! repository for all directories.
$ cnames = "/names=(shortened,as_is)/repository=''base_dir'"
$!
$! Set the compiler options for GNV CC wrapper to inherit.
$ cc :== cc'clist''cnames'/nested_include_directory=none
$ cxx :== cxx'clist''cnames'/nested_include_directory=none
$ pointer_size = "32"
$! Note 64 bit pointers requires all libraries to either have
$! 64 bit pointers or have #pragma directives.
$! Currently building curl on VMS with 64 bit pointers does not work.
$!
$! A logical name to make it easier to find some of the hacks.
$ define/job gnv_hacks 'base_dir'
$!
$! A logical name to find the [.packages.vms] directory where we started.
$ define/job gnv_packages_vms 'default_dir'
$!
$! Kerberos headers:
$ if f$trnlnm("gssapi") .eqs. ""
$ then
$   if f$search("sys$sysroot:[kerberos]include.dir") .nes. ""
$   then
$       define/job gssapi sys$sysroot:[kerberos.include]
$   endif
$ endif
$!
$! OpenSSL headers
$ if f$trnlnm("openssl") .eqs. ""
$ then
$   if f$trnlnm("ssl$include") .nes. ""
$   then
$       define/job openssl ssl$include:
$   endif
$ endif
$!
$! C compiler include path.
$ define/job decc$system_include prj_root:[.include.curl],-
    [-.packages.vms],-
    ssl$include:,gnv$gnu:[usr.include],-
    gnv$gnu:[usr.include.libz],gnv$gnu:[include],-
    gnv$zlib_include:,-
    sys$sysroot:[kerberos.include]
$!
$! Set up a include list for the compiler to find all the header files
$! that they need.
$!
$ define/job decc$user_include src_root:[.include.curl]
$ define ssl_lib sys$library:
$!
$! Calculate what is needed in the option files
$ libzshr_line = ""
$ try_shr = "gnv$libzshr''pointer_size'"
$ if f$search(try_shr) .nes. "" then libzshr_line = "''try_shr'/share"
$ if (libzshr_line .eqs. "")
$ then
$   try_shr = "sys$share:" + try_shr
$   if f$search("''try_shr'.exe") .nes. ""
$   then
$       libzshr_line = "''try_shr'/share"
$   endif
$ endif
$!
$! Kerberos
$ gssrtlshr_line = ""
$ try_shr = "sys$share:gss$rtl"
$ if f$search("''try_shr'.exe") .nes. ""
$ then
$   gssrtlshr_line = "''try_shr'/share"
$ endif
$!
$! HP OpenSSL
$ libcryptoshr_line = ""
$ try_shr = "sys$share:ssl$libcrypto_shr''pointer_size'"
$ if f$search("''try_shr'.exe") .nes. ""
$ then
$   libcryptoshr_line = "''try_shr'/share"
$ endif
$!
$ libsslshr_line = ""
$ try_shr = "sys$share:ssl$libssl_shr''pointer_size'"
$ if f$search("''try_shr'.exe") .nes. ""
$ then
$   libsslshr_line = "''try_shr'/share"
$ endif
$!
$!
$! Copy over the gnv$conftest* files to base directory.
$!-----------------------------------------------------
$ copy 'default_dir'gnv_conftest.c_first 'base_dir'gnv$conftest.c_first
$ create 'base_dir'gnv$conftest.opt
$ open/append opt 'base_dir'gnv$conftest.opt
$ if libzshr_line .nes. "" then write opt libzshr_line
$ if libcryptoshr_line .nes. "" then write opt libcryptoshr_line
$ if libsslshr_line .nes. "" then write opt libsslshr_line
$ close opt
$ purge 'base_dir'gnv$conftest.*
$ rename 'base_dir'gnv$conftest.* ;1
$!
$!
$!
$! GNV helper files for building the test curl binary.
$!-----------------------------------------------
$ create [.src]gnv$curl.opt
$ open/append opt [.src]gnv$curl.opt
$ write opt "gnv_packages_vms:curlmsg.obj"
$ if libzshr_line .nes. "" then write opt libzshr_line
$ if gssrtlshr_line .nes. "" then write opt gssrtlshr_line
$ if libcryptoshr_line .nes. "" then write opt libcryptoshr_line
$ if libsslshr_line .nes. "" then write opt libsslshr_line
$ close opt
$ purge [.src]gnv$*.*
$ rename [.src]gnv$*.* ;1
$!
$!
$! Create the libcurl
$!------------------------------------------------------
$ create 'default_dir'gnv_libcurl_linker.opt
$ open/append opt 'default_dir'gnv_libcurl_linker.opt
$ if libzshr_line .nes. "" then write opt libzshr_line
$ if gssrtlshr_line .nes. "" then write opt gssrtlshr_line
$ if libcryptoshr_line .nes. "" then write opt libcryptoshr_line
$ if libsslshr_line .nes. "" then write opt libsslshr_line
$ close opt
$!
$!
$! Create the template linker file
$!---------------------------------
$ create 'default_dir'gnv_template_linker.opt
$ open/append opt 'default_dir'gnv_template_linker.opt
$ write opt "gnv_vms_common:vms_curl_init_unix.obj"
$ if libzshr_line .nes. "" then write opt libzshr_line
$ if gssrtlshr_line .nes. "" then write opt gssrtlshr_line
$ if libcryptoshr_line .nes. "" then write opt libcryptoshr_line
$ if libsslshr_line .nes. "" then write opt libsslshr_line
$ close opt
$!
$! Copy over the gnv$*.opt files for [.docs.examples]
$!----------------------------------------------------
$ if examples .ne. 0
$ then
$   example_apps = "10-at-a-time,anyauthput,certinfo,cookie_interface,debug"
$   example_apps = example_apps + ",fileupload,fopen,ftpget,ftpgetresp"
$   example_apps = example_apps + ",ftpupload,getinfo,getinmemory"
$   example_apps = example_apps + ",http-post,httpcustomheader,httpput"
$   example_apps = example_apps + ",https,multi-app,multi-debugcallback"
$   example_apps = example_apps + ",multi-double,multi-post,multi-single"
$   example_apps = example_apps + ",persistent,post-callback,postit2"
$   example_apps = example_apps + ",sendrecv,sepheaders,simple,simplepost"
$   example_apps = example_apps + ",simplessl"
$!
$   i = 0
$example_loop:
$      ap_name = f$element(i, ",", example_apps)
$      if ap_name .eqs. "," then goto example_loop_end
$      if ap_name .eqs. "" then goto example_loop_end
$      copy 'default_dir'gnv_template_linker.opt -
           [.docs.examples]gnv$'ap_name'.opt
$      i = i + 1
$      goto example_loop
$example_loop_end:
$!
$! clean up the copy.
$    purge [.docs.examples]gnv$*.opt
$    rename [.docs.examples]gnv$*.opt ;1
$ endif
$!
$!
$ if tests .ne. 0
$ then
$   libtest_apps = "lib500,lib501,lib502,lib503,lib504,lib505,lib506,lib507"
$   libtest_apps = libtest_apps + ",lib508,lib510,lib511,lib512,lib513,lib514"
$   libtest_apps = libtest_apps + ",lib515,lib516,lib517,lib518,lib519,lib520"
$   libtest_apps = libtest_apps + ",lib521,lib523,lib524,lib525,lib526,lib527"
$   libtest_apps = libtest_apps + ",lib529,lib530,lib532,lib533,lib536,lib537"
$   libtest_apps = libtest_apps + ",lib539,lib540,lib541,lib542,lib543,lib544"
$   libtest_apps = libtest_apps + ",lib545,lib547,lib548,lib549,lib552,lib553"
$   libtest_apps = libtest_apps + ",lib554,lib555,lib556,lib557,lib558,lib559"
$   libtest_apps = libtest_apps + ",lib560,lib562,lib564"
$   i = 0
$libtest_loop:
$     ap_name = f$element(i, ",", libtest_apps)
$     if ap_name .eqs. "," then goto libtest_loop_end
$     if ap_name .eqs. "" then goto libtest_loop_end
$     copy 'default_dir'gnv_template_linker.opt -
          [.tests.libtest]gnv$'ap_name'.opt
$     i = i + 1
$     goto libtest_loop
$libtest_loop_end:
$!
$! clean up the copy.
$   purge [.tests.libtest]gnv$*.opt
$   rename [.tests.libtest]gnv$*.opt ;1
$ endif
$!
$!
$! Build the Message file.
$!--------------------------
$ if f$search("[.packages.vms]curlmsg.obj") .eqs. ""
$ then
$   message [.packages.vms]curlmsg.msg/object=[.packages.vms]
$ endif
$ if f$search("gnv$curlmsg.exe") .eqs. ""
$ then
$   link/share=gnv$curlmsg.exe [.packages.vms]curlmsg.obj
$ endif
$!
$!
$!
$! Need to build the common init module.
$!-------------------------------------------
$ init_obj = "[.packages.vms]curl_crtl_init.obj"
$ if f$search(init_obj) .eqs. ""
$ then
$   cc'cflags' 'default_dir'curl_crtl_init.c/obj='init_obj'
$   purge 'init_obj'
$   rename 'init_obj' ;1
$ endif
$!
$all_exit:
$!
$ set def 'default_dir'
$!
$! Verify can break things in bash, especially in Configure scripts.
$ set nover
$ exit
