$! BUILD_VMS.COM
$!
$! I've taken the original build_vms.com, supplied by Nico Baggus, if
$! memory serves me correctly, and made some modifications.
$!
$! SSL support is controlled by logical names.  If SSL$INCLUDE is
$! defined, then it is assumed that HP's SSL product has been installed.
$! If OPENSSL is defined, but SSL$INCLUDE is not, then OpenSSL will be
$! used.  If neither logical name is defined, then SSL support will not
$! be compiled/linked in.  Command-line options NOHPSSL and NOSSL can be
$! specified to override the automatic SSL selection.
$!
$! Command-line Options:
$!
$!    CLEAN     Delete product files for this host architecture.  (No
$!              build done.)
$!    CLEAN_ALL Delete product files for all host architectures.  (No
$!              build done.)
$!
$!    64        Compile with 64-bit pointers.
$!		Note, you must match the pointer size that the OpenSSL
$!		shared image expects.
$!		Currently curl is not building properly with 64 bit pointers
$!		on VMS because it is trying to cast pointers to 32 bit
$!		integers.
$!    CCQUAL=x  Add "x" to the C compiler qualifiers.
$!		Default qualifiers are:
$!		/standard=relaxed
$!		/names=(as_is, shortened)
$!		/repository=[.'arch']
$!		/nested_include_directory=none
$!		/define=(_LARGEFILE=1,_USE_STD_STAT=1) (non-vax)
$!		/float=ieee/ieee_mode=denorm_results (non-vax)
$!    DEBUG     Compile debug and nooptimize
$!		Alpha/IA64 always compiles /debug.
$!		Always link a debug image.
$!    NOIEEE    Do not use IEEE floating point.  (Alpha/I64)
$!		VAX must use DFLOAT
$!    NOLARGE   Disable large-file support if large file support available.
$!		(Non-VAX, VMS >= V7.2.)
$!    NOLDAP    Disable LDAP support if LDAP is available.
$!    NOKERBEROS   Disable Kerberos support if Kerberos is available.
$!    LIST      Create C compiler listings and linker maps.
$!		/list/show=(expan,includ)/machine
$!    FULLLIST  Full detailed listing.
$!		/list/show=(all, nomessages)/machine
$!    NOHPSSL   Don't use HP SSL, even if available.
$!		Note, you must match the pointer size that the OpenSSL
$!		shared image expects.  This procedure will select the
$!		correct HP OpenSSL image.
$!    NOSSL     Don't use any SSL, even if available.
$!    OSSLOLB   Use OpenSSL object libraries (.OLB), even if shared
$!              images (.EXE) are available.
$!    NOZLIB	Don't use GNV$ZLIB shared image even if available.
$!
$! DCL Symbols:
$!
$!    CURL_CCDEFS="c_macro_1=value1 [, c_macro_2=value2 [...]]"
$!              Compile with these additional C macros defined.
$!
$! Revisions:
$!
$!  2-DEC-2003, MSK, the "original" version.
$!                   It works for me.  Your mileage may vary.
$! 13-JAN-2004, MSK, moved this procedure to the [.packages.vms] directory
$!                   and updated it to do hardware dependent builds.
$! 29-JAN-2004, MSK, moved logical defines into defines.com
$!  6-FEB-2004, MSK, put in various SSL support bits
$!  9-MAR-2004, MSK, the config-vms.h* files are now copied to the lib and
$!                   src directories as curl_config.h.
$! 15-MAR-2004, MSK, All of the curlmsg*.* files have also been moved to
$!                   this build directory.  They will be copied to the src
$!                   directory before build.  The .msg file will be compiled
$!                   to get the .obj for messages, but the .h and .sdl files
$!                   are not automatically created since they partly rely on
$!                   the freeware SDL tool.
$!  8-FEB-2005, MSK, merged the two config-vms.h* files into one that uses
$!                   USE_SSLEAY to define if the target has SSL support built
$!                   in.  Changed the cc/define parameter accordingly.
$! 11-FEB-2005, MSK, If [--.LIB]AMIGAOS.C and NWLIB.C are there, rename them
$! 23-MAR-2005, MSK, relocated cc_qual define so that DEBUG option would work
$! 25-APR-2007, STL, allow compilation in 64-bit mode.
$! 13-DEC-2009. SMS, Changed to skip unwanted source files without
$!                   renaming the original files.
$!                   Eliminated needless, persistent logical names.
$!                   Added CURL_CCDEFS DCL symbol for user-specified C
$!                   macro definitions.
$!                   Added CLEAN and CLEAN_ALL options.
$!                   Added CCQUAL option for user-specified C compiler
$!                   qualifiers.
$!                   Added IEEE option for IEEE floating point (Alpha).
$!                   Added LARGE option for large-file support.
$!                   Added OSSLOLB option, and support for OpenSSL
$!                   shared images.
$!                   Changed to put listing and map files into lisdir:.
$!                   Changed to avoid case confusion on ODS5 disks.
$!                   Added more default dev:[dir] save+restore.
$!                   Moved remaining "defines.com" code (back) into
$!                   here, eliminating the hard-coded OpenSSL nonsense.
$!                   Changed to use F$GETSYI("ARCH_NAME") (or
$!                   equivalent) to name architecture-specific product
$!                   file destination directory, and to create the
$!                   directory if needed (obviating inclusion of these
$!                   directories and dummy files in the distribution
$!                   kit).
$!                   Changed the "compile" subroutine to break the CC
$!                   command across multiple lines to avoid DCL
$!                   line-too-long problems.
$!                   Changed "vo_c" messages to show the CC qualifiers
$!                   once, not with every compile command.
$! 01-Jan-2013	J. Malmberg
$!		     VMS build procedures need to be able to work with
$!		     the default set to a search list, with created or
$!		     modified files only in the first member of the search
$!		     list.
$!		     Whitespace change to be more compatible with current
$!		     practices.
$!		     One pass option parsing instead of loop.
$!		     GNV ZLIB shared image support.
$!		     KERBEROS support where available.
$!		     LDAP default to on where available
$!		     LARGEFILE default to on where available
$!		     IEEE float default to on where available.
$!		     Generate the curl_config.h file from system inspection.
$!		     Linker finds ldap with out option file.
$! 13-Mar-2013, Tom Grace
$!                   Added missing slash in cc_full_list.
$!                   Removed unwanted extra quotes inside symbol tool_main
$!                   for non-VAX architectures that triggered link failure.
$!                   Replaced curl_sys_inc with sys_inc.
$! 19-Mar-2013, John Malmberg
$!                   symbol tool_main needs to be quoted when parse style is
$!                   set to exended in versions of VMS greater than 7.3-1.
$!                   Remove curlbuild.h generation as it should be pre-built
$!                   in the curl release or daily tarball.
$!
$!===========================================================================
$!
$!
$! Save the original default dev:[dir], and arrange for its restoration
$! at exit.
$!------------------------------------------------------------------------
$ curl = ""
$ orig_def = f$environment("DEFAULT")
$ on error then goto Common_Exit
$ on control_y then goto Common_Exit
$!
$ ctrl_y  = 1556
$ proc = f$environment("PROCEDURE")
$ proc_fid = f$file_attributes(proc, "FID")
$ proc_dev = f$parse(proc, , , "DEVICE")
$ proc_dir = f$parse(proc, , , "DIRECTORY")
$ proc_name = f$parse(proc, , , "NAME")
$ proc_type = f$parse(proc, , , "TYPE")
$ proc_dev_dir = proc_dev + proc_dir
$!
$! Have to manually parse the device for a search list.
$! Can not use the f$parse() as it will return the first name
$! in the search list.
$!
$ orig_def_dev = f$element(0, ":", orig_def) + ":"
$ if orig_def_dev .eqs. "::" then orig_def_dev = "sys$disk:"
$ test_proc = orig_def_dev + proc_dir + proc_name + proc_type
$!
$! If we can find this file using the default directory
$! then we know that we should use the original device from the
$! default directory which could be a search list.
$!
$ test_proc_fid = f$file_attributes(test_proc, "FID")
$!
$ if (test_proc_fid .eq. proc_fid)
$ then
$   proc_dev_dir = orig_def_dev + proc_dir
$ endif
$!
$!
$! Verbose output message stuff.  Define symbol to "write sys$output" or "!".
$! vo_c - verbose output for compile
$! vo_l - link
$! vo_o - object check
$!
$ vo_c := "write sys$output"
$ vo_l := "write sys$output"
$ vo_o := "!"
$!
$! Determine the main distribution directory ("[--]") in an
$! ODS5-tolerant (case-insensitive) way.  (We do assume that the only
$! "]" or ">" is the one at the end.)
$!
$! Some non-US VMS installations report ">" for the directory delimiter
$! so do not assume that it is "]".
$!
$ orig_def_len = f$length(orig_def)
$ delim = f$extract(orig_def_len - 1, 1, orig_def)
$!
$ set default 'proc_dev_dir'
$ set default [--]
$ base_dev_dir = f$environment("default")
$ top_dev_dir = base_dev_dir - delim
$!
$!
$!
$! Define the architecture-specific product file destination directory
$! name(s).
$!
$ parse_style = "TRADITIONAL"
$ if (f$getsyi("HW_MODEL") .lt. 1024)
$ then
$    arch_name = "VAX"
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
$ exedir = proc_dev_dir - delim + ".''arch_name'" + delim
$ lisdir = exedir
$ objdir = exedir
$!
$! When building on a search list, need to do a create to make sure that
$! the output directory exists, since the clean procedure tries to delete
$! it.
$ create/dir 'exedir'/prot=o:rwed
$!
$! Interpret command-line options.
$!
$ hpssl = 0
$ ldap = 1
$ list = 0
$ full_list = 0
$ nohpssl = 0
$ nossl = 0
$ openssl = 0
$ osslolb = 0
$ nozlib = 0
$ nokerberos = 0
$ cc_names = "/names=(shortened, as_is)/repository='exedir'
$ cc_defs = "HAVE_CONFIG_H=1"
$ cc_list = "/list='objdir'/show=(expan, includ)/machine
$ cc_full_list = "/list='objdir'/show=(all, nomessages)/machine
$ link_qual = ""
$ if arch_name .eqs. "VAX"
$ then
$    cc_debug = "/nodebug/optimize"
$    !cc_defs = cc_defs + ""
$    cc_float = ""
$    cc_large = ""
$ else
$    cc_debug = "/debug/optimize"
$    cc_defs = cc_defs + ",_USE_STD_STAT"
$    cc_float = "/float=ieee/ieee_mode=denorm_results"
$    cc_large = ",_LARGEFILE"
$ endif
$ cc_qual1 = ""
$ cc_qual2 = ""
$ if (f$type(CURL_CCDEFS) .nes. "")
$ then
$    CURL_CCDEFS = f$edit(CURL_CCDEFS, "TRIM")
$    cc_defs = cc_defs + ", " + CURL_CCDEFS
$ endif
$ msg_qual = "/object = ''objdir'"
$ ssl_opt = ""
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
$ if f$locate(",clean,", args_lower) .lt. args_lower_len
$    then
$       prods = "''exedir'*.*;*"
$   if (f$search(prods) .nes. "") then delete /log 'prods'
$   prods = proc_dev_dir + arch_name + ".DIR;1"
$   if (f$search(prods) .nes. "") then set prot=o:rwed 'prods'
$   if (f$search(prods) .nes. "") then delete /log 'prods'
$   file = "[]config_vms.h"
$   if f$search(file) .nes. "" then delete/log 'file';*
$   file = "[.lib]config_vms.h"
$   if f$search(file) .nes. "" then delete/log 'file';*
$       goto Common_Exit
$    endif
$!
$ if f$locate(",clean_all,", args_lower) .lt. args_lower_len
$    then
$   prods = proc_dev_dir - delim + ".ALPHA" + delim + "*.*;*"
$   if (f$search(prods) .nes. "") then delete /log 'prods'
$   prods = proc_dev_dir + "ALPHA" + ".DIR;1"
$   if (f$search(prods) .nes. "") then set prot=o:rwed 'prods'
$   if (f$search(prods) .nes. "") then delete /log 'prods'
$   prods = proc_dev_dir - delim + ".IA64" + delim + "*.*;*"
$   if (f$search(prods) .nes. "") then delete /log 'prods'
$   prods = proc_dev_dir + "IA64" + ".DIR;1"
$   if (f$search(prods) .nes. "") then set prot=o:rwed 'prods'
$   if (f$search(prods) .nes. "") then delete /log 'prods'
$   prods = proc_dev_dir - delim + ".VAX" + delim + "*.*;*"
$   if (f$search(prods) .nes. "") then delete /log 'prods'
$   prods = proc_dev_dir + "VAX"+ ".DIR;1"
$   if (f$search(prods) .nes. "") then set prot=o:rwed 'prods'
$   if (f$search(prods) .nes. "") then delete /log 'prods'
$       goto Common_Exit
$    endif
$!
$ build_64 = 0
$ if f$locate(",64,", args_lower) .lt. args_lower_len
$    then
$   cc_qual1 = cc_qual1 + " /POINTER = 64"
$   build_64 = 1
$    endif
$!
$ args_loc = f$locate(",ccqual=", args_lower)
$ if args_loc .lt. args_lower_len
$    then
$   arg = f$extract(args_loc + 1, args_lower_len, args_lower)
$   arg_val = f$element(0, ",", arg)
$   cc_qual2 = f$element(1, "=", arg_val);
$    endif
$!
$! On Alpha/IA64 no size penalty for compiling /debug/optimize
$! by default.
$ if f$locate(",debug,", args_lower) .lt. args_lower_len
$    then
$   cc_debug = "/debug/nooptimize"
$       goto arg_loop_end
$    endif
$!
$! We normally want IEEE float if it is available.  Programs that are
$! calling libcurl will typically prefer IEEE behavior, unless on the
$! VAX where we have no choice.
$!
$ if f$locate(",noieee,", args_lower) .lt. args_lower_len
$    then
$   cc_float = ""
$       goto arg_loop_end
$    endif
$!
$! Normally we want large file if it is available.
$ if f$locate(",nolarge,", args_lower) .lt. args_lower_len
$    then
$   write sys$output "Handling of large files disabled."
$   cc_large = ""
$       endif
$ if cc_large .nes. ""
$ then
$   cc_defs = cc_defs + cc_large
$    endif
$!
$ if f$locate(",noldap,", args_lower) .lt. args_lower_len
$    then
$   ldap = 0
$    endif
$!
$ if f$locate(",list,", args_lower) .lt. args_lower_len
$    then
$       list = 1
$ endif
$ if f$locate(",fulllist,", args_lower) .lt. args_lower_len
$ then
$    list = 1
$    full_list = 1
$    endif
$!
$ if f$locate(",nohpssl,", args_lower) .lt. args_lower_len
$    then
$       nohpssl = 1
$    endif
$!
$ if f$locate(",nossl,", args_lower) .lt. args_lower_len
$    then
$       nossl = 1
$    endif
$!
$ if f$locate(",osslolb,", args_lower) .lt. args_lower_len
$    then
$       osslolb = 1
$    endif
$!
$ if f$locate(",nozlib,", args_lower) .lt. args_lower_len
$ then
$   nozlib = 1
$ endif
$!
$ if f$locate(",nokerberos,", args_lower) .lt. args_lower_len
$ then
$   nokerberos = 1
$ endif
$!
$!
$! CC /LIST, LINK /MAP, and MESSAGE /LIST are defaults in batch mode,
$! so be explicit when they're not desired.
$!
$
$ if list .eq. 0
$ then
$   cc_qual1 = cc_qual1 + "/nolist"
$   msg_qual = msg_qual + "/nolist"
$ else
$   msg_qual = msg_qual + "/list='objdir'"
$   if (full_list .ne. 0)
$ then
$	cc_qual1 = cc_qual1 + cc_full_list
$   else
$	cc_qual1 = cc_qual1 + cc_list
$   endif
$ endif
$ cc_qual1 = cc_qual1 + cc_names + cc_float + cc_debug
$!
$! Create product directory, if needed.
$!
$ if (f$search(proc_dev_dir + arch_name + ".DIR;1") .eqs. "")
$ then
$    create /directory 'exedir'
$ endif
$!
$! Detect available (but not prohibited) SSL software.
$!
$ libsslshr_line = ""
$ libcryptoshr_line = ""
$ if (.not. nossl)
$ then
$    if (f$trnlnm("OPENSSL") .nes. "")
$    then
$!       cc_defs = cc_defs + ", USE_SSLEAY=1"
$       if ((f$trnlnm("SSL$INCLUDE") .nes. "") .and. (.not. nohpssl))
$       then
$!         Use HP SSL.
$          hpssl = 1
$!
$!	    Older SSL only has lib*_shr32 images
$!-----------------------------------------------
$	    libsslshr = "sys$share:ssl$libssl_shr"
$	    if (f$search("''libsslshr'.exe") .eqs. "") .or. (.not. build_64)
$	    then
$		libsslshr = libsslshr + "32"
$	    endif
$	    libcryptoshr = "sys$share:ssl$libcrypto_shr"
$	    if (f$search("''libcryptoshr'.exe") .eqs. "") .or. (.not. build_64)
$	    then
$		libcryptoshr = libcryptoshr + "32"
$	    endif
$	    libsslshr_line = "''libsslshr'.exe/share"
$	    libcryptoshr_line = "''libcryptoshr'.exe/share"
$       else
$!         Use OpenSSL.  Assume object libraries, unless shared images
$!         are found (and not prohibited).
$!	   TODO: We do not know how to automatically choose based on the
$!	   pointer size.
$!
$          openssl = 1
$	    libsslshr_line = "ssllib:libssl.olb/lib"
$	    libcryptoshr_line = "ssllib:libcrypto.olb/lib"
$          ssl_opt = ", ssllib:libssl.olb /library" + -
            ", ssllib:libcrypto.olb /library"
$          if (osslolb .eq. 0)
$          then
               if ((f$search("ssllib:ssl_libcrypto.exe") .nes. "")  .and. -
                  (f$search("ssllib:ssl_libssl.exe") .nes. ""))
$             then
$!               OpenSSL shared images with "SSL_xxx.EXE names.
$                openssl = 2
$		   libsslshr_line = "ssllib:ssl_libssl_shr.exe/share"
$		   libcryptoshr_line = "ssllib:ssl_libcrypto_shr.exe/share"
$             else
$                  if ((f$search("ssllib:libcrypto.exe") .nes. "") .and. -
                      (f$search("ssllib:libssl.exe") .nes. ""))
$                then
$!                  OpenSSL shared images with "xxx.EXE names.
$                   openssl = 3
$		       libsslshr_line = "ssllib:libssl_shr.exe/share"
$		       libcryptoshr_line = "ssllib:libcrypto_shr.exe/share"
$                endif
$             endif
$          endif
$       endif
$    endif
$ endif
$!
$! LDAP.
$!
$ if f$search("SYS$SHARE:LDAP$SHR.EXE") .eqs. ""
$ then
$   ldap = 0
$ endif
$ if (ldap .eq. 0)
$ then
$!   cc_defs = cc_defs + ", CURL_DISABLE_LDAP=1"
$ else
$   'vo_c' "%CURL-I-BLDHPLDAP, building with HP LDAP support"
$ endif
$!
$! KERBEROS
$ gssrtlshr_line = ""
$ try_shr = "sys$share:gss$rtl"
$ if f$search("''try_shr'.exe") .eqs. ""
$ then
$   nokerberos = 1
$ endif
$ curl_sys_krbinc = ""
$ if nokerberos .eq. 0
$ then
$   'vo_c' "%CURL-I-BLDHPKERBEROS, building with HP KERBEROS support"
$   curl_sys_krbinc = "sys$sysroot:[kerberos.include]"
$   gssrtlshr_line = "''try_shr'/share"
$ endif
$!
$!
$! LIBZ
$ libzshr_line = ""
$ try_shr = "gnv$libzshr"
$ if f$search(try_shr) .eqs. ""
$ then
$   nozlib = 1
$ endif
$ curl_sys_zlibinc = ""
$ if nozlib .eq. 0
$ then
$   'vo_c' "%CURL-I-BLDGNVLIBZ, building with GNV LIBZ support"
$   libzshr_line = "''try_shr'/share"
$   curl_sys_zlibinc = "GNV$ZLIB_INCLUDE:"
$ endif
$!
$!
$! Form CC qualifiers.
$!
$ cc_defs = "/define = (''cc_defs')"
$ cc_qual2 = cc_qual2 + " /object = ''objdir'"
$ cc_qual2 = cc_qual2 + " /include = ([-.lib], [-.src],"
$ cc_qual2 = cc_qual2 + " [-.packages.vms], [-.packages.vms.''arch_name'])"
$ cc_qual2 = cc_qual2 + "/nested_include_directory=none"
$!
$ 'vo_c' "CC opts:", -
  " ''cc_defs'", -
  " ''cc_qual1'", -
  " ''cc_qual2'"
$!
$! Inform the victim of our plans.
$!
$ if (hpssl)
$ then
$    'vo_c' "%CURL-I-BLDHPSSL, building with HP SSL support"
$ else
$    if (openssl .ne. 0)
$    then
$       if (openssl .eq. 1)
$       then
$          'vo_c' -
 "%CURL-I-BLDOSSL_OLB, building with OpenSSL (object library) support"
$       else
$          'vo_c' -
 "%CURL-I-BLDOSSL_EXE, building with OpenSSL (shared image) support"
$       endif
$    else
$       'vo_c' "%CURL-I-BLDNOSSL, building with NO SSL support"
$    endif
$ endif
$!
$! Announce destination and SSL directories.
$!
$ 'vo_c' "   OBJDIR = ''objdir'"
$ 'vo_c' "   EXEDIR = ''exedir'"
$!
$ if (openssl .ne. 0)
$ then
$    ssllib = f$trnlnm("ssllib")
$    if (ssllib .eqs. "")
$    then
$        ssllib = "(undefined)"
$    endif
$    'vo_c' "   SSLLIB = ''ssllib'"
$!
$! TODO: Why are we translating the logical name?
$! The logical aname used to find the shared image should just be used
$! as translating it could result in the wrong location at run time.
$    if (openssl .eq. 1)
$    then
$       ossl_lib1 = f$trnlnm("ssllib")+ "LIBSSL.OLB"
$       ossl_lib2 = f$trnlnm("ssllib")+ "LIBCRYPTO.OLB"
$       msg = "object libraries"
$    else
$       if (openssl .eq. 2)
$       then
$          ossl_lib1 = f$trnlnm("ssllib")+ "SSL_LIBSSL.EXE"
$          ossl_lib2 = f$trnlnm("ssllib")+ "SSL_LIBCRYPTO.EXE"
$       else
$          ossl_lib1 = f$trnlnm("ssllib")+ "LIBSSL.EXE"
$          ossl_lib2 = f$trnlnm("ssllib")+ "LIBCRYPTO.EXE"
$       endif
$       msg = "shared images"
$    endif
$    if ((f$search(ossl_lib1) .eqs. "") .or. -
      (f$search(ossl_lib2) .eqs. ""))
$    then
$       write sys$output "Can't find OpenSSL ''msg':"
$       write sys$output "   ''ossl_lib1'"
$       write sys$output "   ''ossl_lib2'"
$       goto Common_Exit
$    endif
$ endif
$!
$! Define the "curl" (process) logical name for "#include <curl/xxx.h>".
$!
$ curl = f$trnlnm("curl", "LNM$PROCESS")
$ if (curl .nes. "")
$ then
$    write sys$output ""
$    write sys$output -
 "Process logical name ""curl"" is already defined, but this procedure"
$    write sys$output -
 "would override that definition.  Use a command like"
$    write sys$output -
 "      deassign /process curl"
$    write sys$output -
 "to cancel that logical name definition, and then and re-run this procedure."
$    write sys$output ""
$    goto Common_Exit
$ endif
$ curl_logical = top_dev_dir + ".include.curl" + delim
$ curl_sys_inc2 = curl_logical
$ curl_sys_inc1 = top_dev_dir + ".include" + delim
$! define curl 'top_dev_dir'.include.curl'delim'
$!
$! Generate config file into the product directory.
$!
$! call MoveIfDiff [.lib]config-vms.h 'objdir'curl_config.h
$!
$conf_params = ""
$if nossl .ne. 0 then conf_params = conf_params + ",nossl"
$if nohpssl .ne. 0 then conf_params = conf_params + ",nohpssl,"
$if ldap .eq. 0 then conf_params = conf_params + ",noldap,"
$if nozlib .ne. 0 then conf_params = conf_params + ",nozlib,"
$if nokerberos .ne. 0 then conf_params = conf_params + ",nokerberos"
$conf_params = conf_params - ","
$!
$!
$new_conf = f$search("''objdir'curl_config.h")
$if new_conf .eqs. ""
$then
$!   set ver
$   write sys$output "Generating curl custom config_vms.h"
$   @'proc_dev_dir'generate_config_vms_h_curl.com ''conf_params'
$!
$   write sys$output "Generating curl_config.h"
$   conf_in = f$search("[.lib]curl_config*.*in")
$   if conf_in .eqs. ""
$   then
$	write sys$output "Can not find [.lib]curl_config*.*in file!"
$	goto common_exit
$   endif
$   @'proc_dev_dir'config_h.com 'conf_in'
$   copy config.h 'objdir'curl_config.h
$   delete config.h;
$!   set nover
$endif
$!
$!
$!
$ on control_y then goto Common_Exit
$!
$ set default 'proc_dev_dir'
$ sys_inc = "''curl_sys_inc1', ''curl_sys_inc2', ''curl_logical'"
$ if curl_sys_krbinc .nes. ""
$ then
$   sys_inc = sys_inc + ",''curl_sys_krbinc'"
$ endif
$ if curl_sys_zlibinc .nes. ""
$ then
$   sys_inc = sys_inc + ",''curl_sys_zlibinc'"
$ endif
$ call build "[--.lib]" "*.c" "''objdir'CURLLIB.OLB" "amigaos, nwlib, nwos"
$ if ($status .eq. ctrl_y) then goto Common_Exit
$ call build "[--.src]" "*.c" "''objdir'CURLSRC.OLB"
$ if ($status .eq. ctrl_y) then goto Common_Exit
$ call build "[]" "*.msg" "''objdir'CURLSRC.OLB"
$ if ($status .eq. ctrl_y) then goto Common_Exit
$!
$!
$ if (openssl .ne. 0)
$ then
$    if (openssl .eq. 1)
$    then
$       'vo_l' "%CURL-I-LINK_OSSL, linking with OpenSSL (object library)"
$    else
$       'vo_l' "%CURL-I-LINK_HPSSL, linking with OpenSSL (shared image)"
$    endif
$ else
$    if (hpssl)
$    then
$       'vo_l' "%CURL-I-LINK_HPSSL, linking with HP SSL"
$    else
$       'vo_l' "%CURL-I-LINK_NOSSL, linking with NO SSL support"
$    endif
$ endif
$!
$!
$! GNV helper files for building the test curl binary.
$!-----------------------------------------------
$create 'exedir'gnv$curl.opt
$open/append opt 'exedir'gnv$curl.opt
$if libzshr_line .nes. "" then write opt libzshr_line
$if gssrtlshr_line .nes. "" then write opt gssrtlshr_line
$if libcryptoshr_line .nes. "" then write opt libcryptoshr_line
$if libsslshr_line .nes. "" then write opt libsslshr_line
$close opt
$!
$!
$! Create the libcurl
$!------------------------------------------------------
$create 'exedir'gnv_libcurl_linker.opt
$open/append opt 'exedir'gnv_libcurl_linker.opt
$if libzshr_line .nes. "" then write opt libzshr_line
$if gssrtlshr_line .nes. "" then write opt gssrtlshr_line
$if libcryptoshr_line .nes. "" then write opt libcryptoshr_line
$if libsslshr_line .nes. "" then write opt libsslshr_line
$close opt
$!
$!
$! If we are not on VAX, then we want the debug symbol table in
$! a separate file.
$! VAX needs the tool_main unquoted in uppercase,
$! Alpha and IA64 need tool_main quoted in exact case when parse style is
$! extended.
$ link_dsf1 = ""
$ link_dsf2 = ""
$ tool_main = "tool_main"
$ if arch_name .nes. "VAX"
$ then
$   if parse_style .eqs. "EXTENDED"
$   then
$      tool_main = """tool_main"""
$   endif
$   link_dsf1 = "/dsf=" + exedir + "CURL.DSF"
$   link_dsf2 = "/dsf=" + exedir + "CURL_DEBUG.DSF"
$ endif
$ if (list .eq. 0)
$ then
$   link_map1 = "/nomap"
$   link_map2 = "/nomap"
$ else
$   link_map1 = "/map=" + exedir + "CURL.MAP"
$   link_map2 = "/map=" + exedir + "CURL_DEBUG.MAP"
$ endif
$!
$!
$! Make a normal image.
$ set ver
$ link 'link_map1' 'link_dsf1' /executable = 'exedir'CURL.EXE -
   'objdir'curlsrc.olb /library /include = ('tool_main', curlmsg), -
   'objdir'curllib.olb /library, -
   'exedir'gnv$curl.opt/opt
$!
$! Also make a debug copy.
$ link/debug 'link_map2' 'link_dsf2' /executable = 'exedir'CURL_DEBUG.EXE -
   'objdir'curlsrc.olb /library /include = ('tool_main', curlmsg), -
   'objdir'curllib.olb /library, -
   'exedir'gnv$curl.opt/opt
$set nover
$!
$ goto Common_Exit
$!
$! Subroutine to build everything with a filetype passed in via P2 in
$! the directory passed in via P1 and put it in the object library named
$! via P3.  Exclude items in P4.
$!
$build:   subroutine
$    build_def = f$environment("default")
$    on control_y then goto EndLoop ! SS$_CONTROLY
$    sts = 1 ! SS$_NORMAL.
$!    set noon
$    set default 'p1'
$    search = p2
$    reset = f$search("reset")
$    if f$search( p3) .eqs. ""
$    then
$       librarian /create /object 'p3'
$    endif
$    reject_list__ = "," + f$edit(p4, "COLLAPSE, UPCASE") + ","
$    reject_list___len = f$length(reject_list__)
$    reset = f$search( "reset", 1)
$Loop:
$    file = f$search( search, 1)
$    if file .eqs. "" then goto EndLoop
$!      Skip a name if it's in the P4 exclusion list.
$       if (p4 .nes. "")
$       then
$          name__ = "," + -
            f$edit(f$parse(file, , , "NAME", "SYNTAX_ONLY"), "UPCASE") + -
            ","
$          if (f$locate(name__, reject_list__) .lt. reject_list___len)
$          then
$             goto Loop
$          endif
$       endif
$       objfile = f$parse("''objdir'.OBJ;", file)
$       obj = f$search(objfile, 2)
$       if (obj .nes. "")
$       then
$          if (f$cvtime(f$file(file,"rdt")) .gts. f$cvtime(f$file(obj,"rdt")))
$          then
$             call compile 'file'
$             sts = $status
$             if .not. sts
$             then
$                goto EndLoop
$             endif
$             librarian /object 'p3' 'objfile'
$          else
$             'vo_o' "%CURL-I-OBJUTD, ", objfile, " is up to date"
$          endif
$       else
$          'vo_o' "%CURL-I-OBJDNE, ", file, " does not exist"
$          call compile 'file'
$          sts = $status
$          if .not. sts
$          then
$             goto EndLoop
$          endif
$          librarian /object 'p3' 'objfile'
$       endif
$    goto Loop
$EndLoop:
$!!!    purge
$    set default 'build_def'
$    exit 'sts'
$ endsubroutine   ! Build
$!
$! Based on the file TYPE, do the right compile command.
$! Only C and MSG supported.
$!
$compile:   subroutine
$    on control_y then return ctrl_y ! SS$_CONTROLY
$!    set noon
$    file = p1
$    qual = p2+ p3+ p4+ p5+ p6+ p7+ p8
$    typ = f$edit(f$parse(file, , , "TYPE"), "UPCASE") - "."
$    if (typ .eqs. "C")
$    then
$       'vo_c' "CC (opts) ", file
$	define/user curl 'curl_logical'
$	if curl_sys_krbinc .nes. "" then define/user gssapi 'curl_sys_krbinc'
$	define/user decc$system_include 'sys_inc'
$       CC 'cc_defs' -
         'cc_qual1' -
         'cc_qual2' -
         'file'
$    else
$       cmd_msg = "MESSAGE " + msg_qual
$       x = cmd_'typ'
$       'vo_c' x, " ", file
$       'x' 'file'
$    endif
$ ENDSUBROUTINE   ! Compile
$!
$! Do a diff of the file specified in P1 with that in P2.  If different
$! copy P1 to P2.  This also covers if P2 doesn't exist, but not if P2
$! is an invalid filespec.
$!
$MoveIfDiff:  subroutine
$    set NoOn
$    define /user_mode sys$error nl:
$    define /user_mode sys$output nl:
$    differences 'p1' 'p2'
$    status = $status
$    if (status .ne. %X006C8009) ! if status is not "no diff"
$    then
$       copy 'p1' 'p2'
$       purge /nolog 'p2'
$    endif
$    on control_y then return ctrl_y ! SS$_CONTROLY
$ ENDSUBROUTINE   ! MoveIfDiff
$!
$Common_Exit:
$ set default 'orig_def'
$ exit
