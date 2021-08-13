$! File: gnv_link_curl.com
$!
$! $Id$
$!
$! File to build images using gnv$libcurl.exe
$!
$! Copyright 2009 - 2021, John Malmberg
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
$! 10-Jun-2009  J. Malmberg
$!============================================================================
$!
$! Save this so we can get back.
$ default_dir = f$environment("default")
$ define/job gnv_packages_vms 'default_dir'
$!
$ on warning then goto all_exit
$!
$! On VAX, we need to generate a Macro transfer vector.
$ parse_style = "TRADITIONAL"
$ if (f$getsyi("HW_MODEL") .lt. 1024)
$ then
$   @generate_vax_transfer.com
$   arch_name = "VAX"
$ else
$    arch_name = ""
$    arch_name = arch_name + f$edit(f$getsyi("ARCH_NAME"), "UPCASE")
$    if (arch_name .eqs. "") then arch_name = "UNK"
$!
$!   Extended parsing option starts with VMS 7.3-1.
$!   There is no 7.4, so that simplifies the parse a bit.
$!
$    node_swvers = f$getsyi("node_swvers")
$    version_patch = f$extract(1, f$length(node_swvers), node_swvers)
$    maj_ver = f$element(0, ".", version_patch)
$    min_ver_patch = f$element(1, ".", version_patch)
$    min_ver = f$element(0, "-", min_ver_patch)
$    patch = f$element(1, "-", min_ver_patch)
$    if patch .eqs. "-" then patch = ""
$    parse_x = 0
$    if maj_ver .ges. "8"
$    then
$       parse_x = 1
$    else
$       if maj_ver .eqs. "7" .and. min_ver .ges. "3" .and. patch .nes. ""
$       then
$          parse_x = 1
$       endif
$    endif
$    if parse_x
$    then
$       parse_style = f$getjpi("", "parse_style_perm")
$    endif
$ endif
$!
$!
$! Move to where the base directories.
$ set def [--]
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
$! Need to build the common init module.
$!-------------------------------------------
$ cflags = "/list/show=(expan,includ)"
$ init_obj = "[.packages.vms]curl_crtl_init.obj"
$ if f$search(init_obj) .eqs. ""
$ then
$   cc'cflags' 'default_dir'curl_crtl_init.c/obj='init_obj'
$ endif
$ purge 'init_obj'
$ rename 'init_obj' ;1
$!
$!
$! Need to build the module to test the HP OpenSSL version
$!--------------------------------------------------------
$ if arch_name .nes. "VAX"
$ then
$   rpt_obj = "[.packages.vms]report_openssl_version.obj
$   if f$search(rpt_obj) .eqs. ""
$   then
$       cc'cflags' 'default_dir'report_openssl_version.c/obj='rpt_obj'
$   endif
$   purge 'rpt_obj'
$   rename 'rpt_obj' ;1
$!
$   link/exe='default_dir'report_openssl_version.exe 'rpt_obj'
$   report_openssl_version := $'default_dir'report_openssl_version.exe
$ endif
$!
$!
$ base_link_opt_file = "[.packages.vms.''arch_name']gnv_libcurl_linker.opt"
$ share_link_opt_file = "[.packages.vms.''arch_name']gnv_ssl_libcurl_linker.opt"
$ if f$search(base_link_opt_file) .eqs. ""
$ then
$   base_link_opt_file = "[.packages.vms]gnv_libcurl_linker.opt"
$   share_link_opt_file = "[.packages.vms]gnv_ssl_libcurl_linker.opt"
$   if f$search(base_link_opt_file) .eqs. ""
$   then
$       write sys$output "Can not find base library option file!"
$       goto all_exit
$   endif
$ endif
$!
$! Create the a new option file with special fixup for HP SSL
$! For a shared image, we always want ZLIB and 32 bit HPSSL
$!
$ if f$search("gnv$libzshr32") .eqs. ""
$ then
$   write sys$output "VMSPORTS/GNV LIBZ Shared image not found!"
$   goto all_exit
$ endif
$!
$!
$! Need to check the version of the HP SSL shared image.
$!
$! VAX platform can not be checked this way, it appears symbol lookup
$! was disabled.  VAX has not been updated in a while.
$ if arch_name .eqs. "VAX"
$ then
$   hp_ssl_libcrypto32 = "sys$common:[syslib]ssl$libcrypto_shr32.exe"
$   hp_ssl_libssl32 = "sys$common:[syslib]ssl$libssl_shr32.exe"
$   if f$search(hp_ssl_libcrypto32) .nes. ""
$   then
$       use_hp_ssl = 1
$       curl_ssl_libcrypto32 = hp_ssl_libcrypto32
$       curl_ssl_libssl32 = hp_ssl_libssl32
$       curl_ssl_version = "OpenSSL/0.9.6g"
$   else
$       write sys$output "HP OpenSSL Shared images not found!"
$       goto all_exit
$   endif
$ else
$!
$!   Minimum HP version we can use reports:
$!   "OpenSSL 0.9.8w 23 Apr 2012"
$!
$   use_hp_ssl = 0
$   hp_ssl_libcrypto32 = "sys$share:ssl$libcrypto_shr32.exe"
$   hp_ssl_libssl32 = "sys$share:ssl$libssl_shr32.exe"
$   if f$search(hp_ssl_libcrypto32) .nes. ""
$   then
$       curl_ssl_libcrypto32 = hp_ssl_libcrypto32
$       curl_ssl_libssl32 = hp_ssl_libssl32
$       report_openssl_version 'hp_ssl_libcrypto32' hp_ssl_version
$   endif
$!
$   if f$type(hp_ssl_version) .eqs. "STRING"
$   then
$       curl_ssl_version = hp_ssl_version
$       full_version = f$element(1, " ", hp_ssl_version)
$       ver_maj = f$element(0, ".", full_version)
$       ver_min = f$element(1, ".", full_version)
$       ver_patch = f$element(2, ".", full_version)
$!      ! ver_patch is typically both a number and some letters
$       ver_patch_len = f$length(ver_patch)
$       ver_patchltr = ""
$ver_patch_loop:
$           ver_patchltr_c = f$extract(ver_patch_len - 1, 1, ver_patch)
$           if ver_patchltr_c .les. "9" then goto ver_patch_loop_end
$           ver_patchltr = ver_patchltr_c + ver_patchltr
$           ver_patch_len = ver_patch_len - 1
$           goto ver_patch_loop
$ver_patch_loop_end:
$       ver_patchnum = ver_patch - ver_patchltr
$       if 'ver_maj' .ge. 0
$       then
$           if 'ver_min' .ge. 9
$           then
$               if 'ver_patchnum' .ge. 8
$               then
$                   if ver_patchltr .ges. "w" then use_hp_ssl = 1
$               endif
$           endif
$       endif
$set nover
$       if use_hp_ssl .eq. 0
$       then
$           write sys$output -
   " HP OpenSSL version of ""''hp_ssl_version'"" is too old for shared libcurl!"
$       endif
$   else
$       write sys$output "Unable to get version of HP OpenSSL"
$   endif
$!
$   gnv_ssl_libcrypto32 = "gnv$gnu:[lib]ssl$libcrypto_shr32.exe"
$   gnv_ssl_libssl32 = "gnv$gnu:[lib]ssl$libssl_shr32.exe"
$   if f$search(gnv_ssl_libcrypto32) .nes. ""
$   then
$       report_openssl_version 'gnv_ssl_libcrypto32' gnv_ssl_version
$   endif
$!
$   use_gnv_ssl = 0
$   if f$type(gnv_ssl_version) .eqs. "STRING"
$   then
$       gnv_full_version = f$element(1, " ", gnv_ssl_version)
$       gnv_ver_maj = f$element(0, ".", gnv_full_version)
$       gnv_ver_min = f$element(1, ".", gnv_full_version)
$       gnv_ver_patch = f$element(2, ".", gnv_full_version)
$       gnv_ver_patch_len = f$length(gnv_ver_patch)
$       gnv_ver_patchnum = f$extract(0, gnv_ver_patch_len - 1, gnv_ver_patch)
$       gnv_ver_patchltr = f$extract(gnv_ver_patch_len - 1, 1, gnv_ver_patch)
$       if 'gnv_ver_maj' .ge. 0
$       then
$           if 'gnv_ver_min' .ge. 9
$           then
$               if 'gnv_ver_patchnum' .ge. 8
$               then
$                   if gnv_ver_patchltr .ges. "w" then use_gnv_ssl = 1
$               endif
$           endif
$       endif
$       if use_gnv_ssl .eq. 0
$       then
$           write sys$output -
   "GNV OpenSSL version of ""''gnv_ssl_version'" is too old for shared libcurl!"
$       endif
$!
$!      Prefer to break the tie with the lowest supported version
$!      For simplicity, if the GNV image is present, it will be used.
$!      Version tuple is not a simple compare.
$!
$       if use_gnv_ssl .eq. 1 then
$           curl_ssl_libcrypto32 = gnv_ssl_libcrypto32
$           curl_ssl_libssl32 = gnv_ssl_libssl32
$           curl_ssl_version = gnv_ssl_version
$           use_hp_ssl = 0
$       endif
!$!
$   else
$       write sys$output "Unable to get version of GNV OpenSSL"
$   endif
$!
$!  Need to write a release note section about HP OpenSSL
$!
$create 'default_dir'hp_ssl_release_info.txt
$deck
This package is built on with the OpenSSL version listed below and requires
the shared images from the HP OpenSSL product that is kitted with that
version or a compatible later version.

For Alpha and IA64 platforms, see the url below to register to get the
download URL.  The kit will be HP 1.4-467 or later.
  https://h41379.www4.hpe.com/openvms/products/ssl/ssl.html

For VAX, use the same registration, but remove the kit name from any of the
download URLs provided and put in CPQ-VAXVMS-SSL-V0101-B-1.PCSI-DCX_VAXEXE

If your system can not be upgraded to a compatible version of OpenSSL, then
you can extract the two shared images from the kit and place them in the
[vms$common.gnv.lib]directory of the volume that you are installing GNV and
or GNV compatible components like Curl.

If GNV is installed, you must run the GNV startup procedure before these steps
and before installing Curl.


  1.  make sure that [vms$common.gnv.lib] exists by using the following
      commands.  We want the directory to be in lowercase except on VAX.

    $SET PROCESS/PARSE=extend !If not VAX.
    $CREATE/DIR device:[vms$common.gnv.lib]/prot=w:re

  2. Extract the ssl$crypto_shr32.exe and ssl$libssl_shr32.exe images.

    $PRODUCT EXTRACT FILE -
      /select=(ssl$libcrypto_shr32.exe,ssl$libssl_shr32.exe)-
      /source=device:[dir] -
      /options=noconfirm -
      /destination=device:[vms$common.gnv.lib] SSL

The [vms$common.sys$startup}curl_startup.com procedure will then configure
libcurl to use these shared images instead of the system ones.

When you upgrade SSL on VMS to the newer version of HP SSL, then these copies
should be deleted.

$eod
$!
$ open/append sslr 'default_dir'hp_ssl_release_info.txt
$ write sslr "OpenSSL version used for building this kit: ",curl_ssl_version
$ write sslr ""
$ close sslr
$!
$!
$! LIBZ
$ libzshr_line = ""
$ try_shr = "gnv$libzshr32"
$ if f$search(try_shr) .nes. ""
$ then
$   libzshr_line = "''try_shr'/share"
$ else
$   write sys$output "''try_shr' image not found!"
$   goto all_exit
$ endif
$!
$!
$ gssrtlshr_line = ""
$ if arch_name .nes. "VAX"
$ then
$   try_shr = "sys$share:gss$rtl"
$   if f$search("''try_shr'.exe") .nes. ""
$   then
$       gssrtlshr_line = "''try_shr'/share"
$   else
$       write sys$output "''try_shr' image not found!"
$       goto all_exit
$   endif
$ endif
$!
$!
$!
$ if f$search(share_link_opt_file) .eqs. ""
$ then
$   create 'share_link_opt_file'
$   open/append slopt 'share_link_opt_file'
$   if libzshr_line .nes. "" then write slopt libzshr_line
$   if gssrtlshr_line .nes. "" then write slopt gssrtlshr_line
$   write slopt "gnv$curl_ssl_libcryptoshr32/share"
$   write slopt "gnv$curl_ssl_libsslshr32/share"
$   close slopt
$ endif
$!
$! DCL build puts curllib in architecture directory
$! GNV build uses the makefile.
$ libfile = "[.packages.vms.''arch_name']curllib.olb"
$ if f$search(libfile) .nes. ""
$ then
$   olb_file = libfile
$ else
$   ! GNV based build
$   libfile = "[.lib.^.libs]libcurl.a"
$   if f$search(libfile) .nes. ""
$   then
$       olb_file = libfile
$   else
$       write sys$output -
  "Can not build shared image, libcurl object library not found!"
$       goto all_exit
$   endif
$ endif
$!
$gnv_libcurl_share = "''default_dir'gnv$libcurl.exe"
$!
$ if f$search(gnv_libcurl_share) .eqs. ""
$ then
$   if arch_name .nes. "VAX"
$   then
$       define/user gnv$curl_ssl_libcryptoshr32 'curl_ssl_libcrypto32'
$       define/user gnv$curl_ssl_libsslshr32 'curl_ssl_libssl32'
$       link/dsf='default_dir'gnv$libcurl.dsf/share='gnv_libcurl_share' -
            /map='default_dir'gnv$libcurl.map -
            gnv_packages_vms:gnv_libcurl_symbols.opt/opt,-
            'olb_file'/lib,-
            'share_link_opt_file'/opt
$   else
$!      VAX will not allow the logical name hack for the
$!      SSL libcryto library, it is pulling it in twice if I try it.
$       link/share='gnv_libcurl_share'/map='default_dir'gnv$libcurl.map -
            gnv_packages_vms:gnv_libcurl_xfer.opt/opt,-
            'olb_file'/lib,-
            'base_link_opt_file'/opt
$   endif
$ endif
$!
$!
$ if f$search("[.src]curl-tool_main.o") .nes. ""
$ then
$!  From src/makefile.inc:
$!  # libcurl has sources that provide functions named curlx_* that aren't
$!  # part of the official API, but we re-use the code here to avoid
$!  # duplication.
$!
$!
$   if f$search("[.src]curl.exe") .eqs. ""
$   then
$       define/user gnv$libcurl 'gnv_libcurl_share'
$       link'ldebug'/exe=[.src]curl.exe/dsf=[.src]curl.dsf -
           [.src]curl-tool_main.o, [.src]curl-tool_binmode.o, -
           [.src]curl-tool_bname.o, [.src]curl-tool_cb_dbg.o, -
           [.src]curl-tool_cb_hdr.o, [.src]curl-tool_cb_prg.o, -
           [.src]curl-tool_cb_rea.o, [.src]curl-tool_cb_see.o, -
           [.src]curl-tool_cb_wrt.o, [.src]curl-tool_cfgable.o, -
           [.src]curl-tool_convert.o, [.src]curl-tool_dirhie.o, -
           [.src]curl-tool_doswin.o, [.src]curl-tool_easysrc.o, -
           [.src]curl-tool_formparse.o, [.src]curl-tool_getparam.o, -
           [.src]curl-tool_getpass.o, [.src]curl-tool_help.o, -
           [.src]curl-tool_helpers.o, [.src]curl-tool_homedir.o, -
           [.src]curl-tool_hugehelp.o, [.src]curl-tool_libinfo.o, -
           [.src]curl-tool_mfiles.o, -
           [.src]curl-tool_msgs.o, [.src]curl-tool_operate.o, -
           [.src]curl-tool_operhlp.o, [.src]curl-tool_panykey.o, -
           [.src]curl-tool_paramhlp.o, [.src]curl-tool_parsecfg.o, -
           [.src]curl-tool_setopt.o, [.src]curl-tool_sleep.o, -
           [.src]curl-tool_urlglob.o, [.src]curl-tool_util.o, -
           [.src]curl-tool_vms.o, [.src]curl-tool_writeenv.o, -
           [.src]curl-tool_writeout.o, [.src]curl-tool_xattr.o, -
           [.src]curl-strtoofft.o, [.src]curl-strdup.o, [.src]curl-strcase.o, -
           [.src]curl-nonblock.o, gnv_packages_vms:curlmsg.obj,-
           sys$input:/opt
gnv$libcurl/share
gnv_packages_vms:curl_crtl_init.obj
$   endif
$ else
$   curl_exe = "[.src]curl.exe"
$   curl_dsf = "[.src]curl.dsf"
$   curl_main = "[.packages.vms.''arch_name']tool_main.obj"
$   curl_src = "[.packages.vms.''arch_name']curlsrc.olb"
$   curl_lib = "[.packages.vms.''arch_name']curllib.olb"
$   strcase = "strcase"
$   nonblock = "nonblock"
$   warnless = "warnless"
$!
$!  Extended parse style requires special quoting
$!
$   if (arch_name .nes. "VAX") .and. (parse_style .eqs. "EXTENDED")
$   then
$       strcase = """strcase"""
$       nonblock = """nonblock"""
$       warnless = """warnless"""
$   endif
$   if f$search(curl_exe) .eqs. ""
$   then
$       define/user gnv$libcurl 'gnv_libcurl_share'
$       link'ldebug'/exe='curl_exe'/dsf='curl_dsf' -
           'curl_main','curl_src'/lib, -
           'curl_lib'/library/include=-
           ('strcase','nonblock','warnless'),-
           gnv_packages_vms:curlmsg.obj,-
           sys$input:/opt
gnv$libcurl/share
gnv_packages_vms:curl_crtl_init.obj
$   endif
$ endif
$!
$!
$!
$! in6addr_missing so skip building:
$! [.server]sws.o
$! [.server]sockfilt.o
$! [.server]tftpd.o
$!
$!
$ target = "10-at-a-time"
$ if f$search("[.docs.examples]''target'.o") .eqs. ""
$ then
$   write sys$output "examples not built"
$   goto all_exit
$ endif
$ if f$search("[.docs.examples]''target'.exe") .eqs. ""
$ then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$ endif
$!
$!
$ target = "anyauthput"
$ if f$search("[.docs.examples]''target'.exe") .eqs. ""
$ then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$ endif
$!
$!
$ target = "certinfo"
$ if f$search("[.docs.examples]''target'.exe") .eqs. ""
$ then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$ endif
$!
$!
$ target = "cookie_interface"
$ if f$search("[.docs.examples]''target'.exe") .eqs. ""
$ then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$ endif
$!
$!
$ target = "debug"
$ if f$search("[.docs.examples]''target'.exe") .eqs. ""
$ then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$ endif
$!
$!
$ target = "fileupload"
$ if f$search("[.docs.examples]''target'.exe") .eqs. ""
$ then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$ endif
$!
$!
$ target = "fopen"
$ if f$search("[.docs.examples]''target'.exe") .eqs. ""
$ then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$ endif
$!
$!
$target = "ftpget"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "ftpgetresp"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "ftpupload"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "getinfo"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "getinmemory"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "http-post"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "httpcustomheader"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "httpput"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "https"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "multi-app"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "multi-debugcallback"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "multi-double"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "multi-post"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "multi-single"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "persistent"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "post-callback"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "postit2"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "sendrecv"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "sepheaders"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "simple"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "simplepost"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$!
$target = "simplessl"
$if f$search("[.docs.examples]''target'.exe") .eqs. ""
$then
$   define/user gnv$libcurl 'gnv_libcurl_share'
$   link'ldebug'/exe=[.docs.examples]'target'.exe-
    /dsf=[.docs.examples]'target'.dsf -
    [.docs.examples]'target'.o,-
    gnv$'target'.opt/opt,-
    sys$input:/opt
gnv$libcurl/share
$endif
$!
$! =============== End of docs/examples =========================
$!
$!
$all_exit:
$set def 'default_dir'
$exit '$status'
$!
