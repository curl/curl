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
$!    CCQUAL=x  Add "x" to the C compiler qualifiers.
$!    DEBUG     Compile and link with debug.
$!    IEEE      Use IEEE floating point.  (Alpha.)
$!    LARGE     Enable large-file support.  (Non-VAX, VMS >= V7.2.)
$!    LDAP      Enable LDAP support.
$!    LIST      Create C compiler listings and linker maps.
$!    NOHPSSL   Don't use HP SSL, even if available.
$!    NOSSL     Don't use any SSL, even if available.
$!    OSSLOLB   Use OpenSSL object libraries (.OLB), even if shared
$!              images (.EXE) are available.
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
$!                   Changed to use F$GETSYI( "ARCH_NAME") (or
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
$!
$!
$! Save the original default dev:[dir], and arrange for its restoration
$! at exit.
$!
$ curl = ""
$ orig_def = f$environment( "DEFAULT")
$ on error then goto Common_Exit
$ on control_y then goto Common_Exit
$!
$ ctrl_y  = 1556
$ proc = f$environment( "PROCEDURE")
$ proc_dev_dir = -
   f$parse( proc, , , "DEVICE")+ f$parse( proc, , , "DIRECTORY")
$!
$! Verbose output message stuff.  Define symbol to "write sys$output" or "!".
$! vo_c - verbose output for compile
$! vo_l - link
$! vo_o - object check
$!
$ vo_c = "write sys$output"
$ vo_l = "write sys$output"
$ vo_o = "!"
$!
$! Determine the main distribution directory ("[--]") in an
$! ODS5-tolerant (case-insensitive) way.  (We do assume that the only
$! "]" is the one at the end.)
$!
$ set default 'proc_dev_dir'
$ set default [--]
$ top_dev_dir = f$environment( "DEFAULT")- "]"
$!
$! Define the architecture-specific product file destination directory
$! name(s).
$!
$ if (f$getsyi( "HW_MODEL") .lt. 1024)
$ then
$    arch_name = "VAX"
$ else
$    arch_name = ""
$    arch_name = arch_name+ f$edit( f$getsyi( "ARCH_NAME"), "UPCASE")
$    if (arch_name .eqs. "") then arch_name = "UNK"
$ endif
$!
$ exedir = proc_dev_dir- "]"+ ".''arch_name']"
$ lisdir = exedir
$ objdir = exedir
$!
$! Interpret command-line options.
$!
$ hpssl = 0
$ ldap = 0
$ list = 0
$ nohpssl = 0
$ nossl = 0
$ openssl = 0
$ osslolb = 0
$ cc_qual1 = ""
$ cc_qual2 = ""
$ cc_defs = "HAVE_CONFIG_H=1"
$ if (f$type( CURL_CCDEFS) .nes. "")
$ then
$    CURL_CCDEFS = f$edit( CURL_CCDEFS, "TRIM")
$    cc_defs = cc_defs+ ", "+ CURL_CCDEFS
$ endif
$ link_qual = ""
$ msg_qual = "/object = ''objdir'"
$ ssl_opt = ""
$!
$ arg = 1
$arg_loop:
$    p = "p''arg'"
$    arg_val = 'p'
$    if (arg_val .eqs. "") then goto arg_loop_out
$    arg_val = f$edit( arg_val, "upcase")
$!
$    if (arg_val .eqs. "CLEAN")
$    then
$       prods = "''exedir'*.*;*"
$       if (f$search( prods) .nes. "") then delete /log 'prods'
$       prods = proc_dev_dir+ arch_name+ ".DIR;1"
$       if (f$search( prods) .nes. "") then delete /log 'prods'
$       goto Common_Exit
$    endif
$!
$    if (arg_val .eqs. "CLEAN_ALL")
$    then
$       prods = proc_dev_dir- "]"+ ".ALPHA]*.*;*"
$       if (f$search( prods) .nes. "") then delete /log 'prods'
$       prods = proc_dev_dir+ "ALPHA"+ ".DIR;1"
$       if (f$search( prods) .nes. "") then delete /log 'prods'
$       prods = proc_dev_dir- "]"+ ".IA64]*.*;*"
$       if (f$search( prods) .nes. "") then delete /log 'prods'
$       prods = proc_dev_dir+ "IA64"+ ".DIR;1"
$       if (f$search( prods) .nes. "") then delete /log 'prods'
$       prods = proc_dev_dir- "]"+ ".VAX]*.*;*"
$       if (f$search( prods) .nes. "") then delete /log 'prods'
$       prods = proc_dev_dir+ "VAX"+ ".DIR;1"
$       if (f$search( prods) .nes. "") then delete /log 'prods'
$       goto Common_Exit
$    endif
$!
$    if (arg_val .eqs. "64")
$    then
$       cc_qual1 = cc_qual1+ " /POINTER = 64"
$       goto arg_loop_end
$    endif
$!
$    if (f$extract( 0, 6, arg_val) .eqs. "CCQUAL")
$    then
$       opts = f$edit( arg_val, "COLLAPSE")
$       eq = f$locate( "=", opts)
$       cc_qual2 = f$extract( (eq+ 1), 1000, opts)
$       goto arg_loop_end
$    endif
$!
$    if (arg_val .eqs. "DEBUG")
$    then
$       cc_qual1 = cc_qual1+ " /debug /nooptimize"
$       link_qual = link_qual+ " /debug"
$       goto arg_loop_end
$    endif
$!
$    if (arg_val .eqs. "IEEE")
$    then
$       cc_qual1 = cc_qual1+ " /FLOAT = IEEE_FLOAT"
$       goto arg_loop_end
$    endif
$!
$    if (arg_val .eqs. "LARGE")
$    then
$       if (arch_name .eqs. "VAX")
$       then
$          write sys$output """LARGE"" is ignored on VAX."
$       else
$          cc_defs = cc_defs+ ", _LARGEFILE=1"
$       endif
$       goto arg_loop_end
$    endif
$!
$    if (arg_val .eqs. "LDAP")
$    then
$       ldap = 1
$       goto arg_loop_end
$    endif
$!
$    if (f$extract( 0, 4, arg_val) .eqs. "LIST")
$    then
$       list = 1
$       cc_qual1 = cc_qual1+ " /list = ''lisdir' /show = (all, nomessages)"
$       link_qual = link_qual+ " /map = ''lisdir'"
$       msg_qual = msg_qual+ " /list = ''lisdir'"
$       goto arg_loop_end
$    endif
$!
$    if (arg_val .eqs. "NOHPSSL")
$    then
$       nohpssl = 1
$       goto arg_loop_end
$    endif
$!
$    if (arg_val .eqs. "NOSSL")
$    then
$       nossl = 1
$       goto arg_loop_end
$    endif
$!
$    if (arg_val .eqs. "OSSLOLB")
$    then
$       osslolb = 1
$       goto arg_loop_end
$    endif
$!
$    write sys$output "Unrecognized command-line option: ''arg_val'"
$    goto Common_Exit
$!
$arg_loop_end:
$ arg = arg+ 1
$ goto arg_loop
$arg_loop_out:
$!
$! CC /LIST, LINK /MAP, and MESSAGE /LIST are defaults in batch mode,
$! so be explicit when they're not desired.
$!
$ if (list .eq. 0)
$ then
$    cc_qual1 = cc_qual1+ " /nolist"
$    link_qual = link_qual+ " /nomap"
$    msg_qual = msg_qual+ " /nolist"
$ endif
$!
$! Create product directory, if needed.
$!
$ if (f$search( proc_dev_dir+ arch_name+ ".DIR;1") .eqs. "")
$ then
$    create /directory 'exedir'
$ endif
$!
$! Detect available (but not prohibited) SSL software.
$!
$ if (.not. nossl)
$ then
$    if (f$trnlnm( "OPENSSL") .nes. "")
$    then
$       cc_defs = cc_defs+ ", USE_SSLEAY=1"
$       if ((f$trnlnm( "SSL$INCLUDE") .nes. "") .and. (.not. nohpssl))
$       then
$!         Use HP SSL.
$          hpssl = 1
$          ssl_opt = ", ''proc_dev_dir'hpssl_"+ -
            f$getsyi("ARCH_NAME")+ ".opt /options"
$       else
$!         Use OpenSSL.  Assume object libraries, unless shared images
$!         are found (and not prohibited).
$          openssl = 1
$          ssl_opt = ", ssllib:libssl.olb /library"+ -
            ", ssllib:libcrypto.olb /library"
$          if (osslolb .eq. 0)
$          then
              if ((f$search( "ssllib:ssl_libcrypto.exe") .nes. "") .and. -
               (f$search( "ssllib:ssl_libssl.exe") .nes. ""))
$             then
$!               OpenSSL shared images with "SSL_xxx.EXE names.
$                openssl = 2
$                ssl_opt = ", ''proc_dev_dir'openssl_ssl_"+ -
                  f$getsyi("ARCH_NAME")+ ".opt /options"
$             else
$                if ((f$search( "ssllib:libcrypto.exe") .nes. "") .and. -
                  (f$search( "ssllib:libssl.exe") .nes. ""))
$                then
$!                  OpenSSL shared images with "xxx.EXE names.
$                   openssl = 3
$                   ssl_opt = ", ''proc_dev_dir'openssl_"+ -
                     f$getsyi("ARCH_NAME")+ ".opt /options"
$                endif
$             endif
$          endif
$       endif
$    endif
$ endif
$!
$! LDAP.
$!
$ if (ldap .eq. 0)
$ then
$    cc_defs = cc_defs+ ", CURL_DISABLE_LDAP=1"
$ endif
$!
$! Form CC qualifiers.
$!
$ cc_defs = "/define = (''cc_defs')"
$ cc_qual2 = cc_qual2+ " /object = ''objdir'"+ -
   " /include = ([-.lib], [-.src],"+ -
   " [-.packages.vms], [-.packages.vms.''arch_name'])"
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
$    ssllib = f$trnlnm( "ssllib")
$    if (ssllib .eqs. "")
$    then
$        ssllib = "(undefined)"
$    endif
$    'vo_c' "   SSLLIB = ''ssllib'"
$!
$    if (openssl .eq. 1)
$    then
$       ossl_lib1 = f$trnlnm( "ssllib")+ "LIBSSL.OLB"
$       ossl_lib2 = f$trnlnm( "ssllib")+ "LIBCRYPTO.OLB"
$       msg = "object libraries"
$    else
$       if (openssl .eq. 2)
$       then
$          ossl_lib1 = f$trnlnm( "ssllib")+ "SSL_LIBSSL.EXE"
$          ossl_lib2 = f$trnlnm( "ssllib")+ "SSL_LIBCRYPTO.EXE"
$       else
$          ossl_lib1 = f$trnlnm( "ssllib")+ "LIBSSL.EXE"
$          ossl_lib2 = f$trnlnm( "ssllib")+ "LIBCRYPTO.EXE"
$       endif
$       msg = "shared images"
$    endif
$    if ((f$search( ossl_lib1) .eqs. "") .or. -
      (f$search( ossl_lib2) .eqs. ""))
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
$ curl = f$trnlnm( "curl", "LNM$PROCESS")
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
$ define curl 'top_dev_dir'.include.curl]
$!
$! Copy the VMS-specific config file into the product directory.
$!
$ call MoveIfDiff 'proc_dev_dir'config-vms.h 'objdir'curl_config.h
$!
$ on control_y then goto Common_Exit
$!
$ set default 'proc_dev_dir'
$ call build "[--.lib]" "*.c" "''objdir'CURLLIB.OLB" "amigaos, nwlib, nwos"
$ if ($status .eq. ctrl_y) then goto Common_Exit
$ call build "[--.src]" "*.c" "''objdir'CURLSRC.OLB"
$ if ($status .eq. ctrl_y) then goto Common_Exit
$ call build "[]" "*.msg" "''objdir'CURLSRC.OLB"
$ if ($status .eq. ctrl_y) then goto Common_Exit
$!
$ ldap_opt = ""
$ if (ldap .ne. 0) then ldap_opt = ", ''proc_dev_dir'ldap.opt /options"
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
$ link 'link_qual' /executable = 'exedir'CURL.EXE -
   'objdir'curlsrc.olb /library /include = (main, curlmsg), -
   'objdir'curllib.olb /library -
   'ssl_opt' -
   'ldap_opt'
$!
$ goto Common_Exit
$!
$! Subroutine to build everything with a filetype passed in via P2 in
$! the directory passed in via P1 and put it in the object library named
$! via P3.  Exclude items in P4.
$!
$build:   subroutine
$    build_def = f$environment( "default")
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
$    reject_list__ = ","+ f$edit( p4, "COLLAPSE, UPCASE")+ ","
$    reject_list___len = f$length( reject_list__)
$    reset = f$search( "reset", 1)
$Loop:
$    file = f$search( search, 1)
$    if file .eqs. "" then goto EndLoop
$!      Skip a name if it's in the P4 exclusion list.
$       if (p4 .nes. "")
$       then
$          name__ = ","+ -
            f$edit( f$parse( file, , , "NAME", "SYNTAX_ONLY"), "UPCASE")+ -
            ","
$          if (f$locate( name__, reject_list__) .lt. reject_list___len)
$          then
$             goto Loop
$          endif
$       endif
$       objfile = f$parse( "''objdir'.OBJ;", file)
$       obj = f$search( objfile, 2)
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
$    typ = f$edit( f$parse( file, , , "TYPE"), "UPCASE") - "."
$    if (typ .eqs. "C")
$    then
$       'vo_c' "CC (opts) ", file
$       CC 'cc_defs' -
         'cc_qual1' -
         'cc_qual2' -
         'file'
$    else
$       cmd_msg = "MESSAGE "+ msg_qual
$       x = cmd_'typ'
$       'vo_c' x," ",file
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
$    if ( status .ne. %X006C8009) ! if status is not "no diff"
$    then
$       copy 'p1' 'p2'
$       purge /nolog 'p2'
$    endif
$    on control_y then return ctrl_y ! SS$_CONTROLY
$ ENDSUBROUTINE   ! MoveIfDiff
$!
$Common_Exit:
$ set default 'orig_def'
$ if ((curl .eqs. "") .and. (f$trnlnm( "curl", "LNM$PROCESS") .nes. ""))
$ then
$    deassign curl
$ endif
$ exit
