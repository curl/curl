$! BUILD_VMS.COM 
$!
$! I've taken the original build_vms.com, supplied by Nico Baggus, if
$! memory serves me correctly, and made some modifications.
$!
$! SSL support is based on logicals, or lack thereof.  If SSL$INCLUDE
$! is defined, then it assumed that hp's SSL product has been installed.
$! If OPENSSL is defined, but SSL$INCLUDE isn't, then the OpenSSL defined
$! via the defines.com procedure will be used.  If neither logical is 
$! defined, then SSL support will not be compiled/linked in.
$!
$! If CURL_BUILD_NOSSL is defined to anything, then no SSL support will
$! be built in.  This way you can build without SSL support on systems
$! that have it without the "automatic" build/link "features".
$!
$! If CURL_BUILD_NOHPSSL is defined to anything, it will override the
$! SSL$INCLUDE check.  This way you can build against OpenSSL, even if
$! you have hp SSL installed.
$!
$! Parameter(s):
$!
$! P1 - LISTING will create .lis files during the C compile
$!      DEBUG will compile and link with debug
$!
$! Revisions:
$!
$!  2-DEC-2003, MSK, the "original" version. <marty@barra.com>
$!                   It works for me.  Your mileage may vary.
$! 13-JAN-2004, MSK, moved this procedure to the [.packages.vms] directory
$!                   and updated it to do hardware dependant builds.
$! 29-JAN-2004, MSK, moved logical defines into defines.com
$!  6-FEB-2004, MSK, put in various SSL support bits
$!  9-MAR-2004, MSK, the config-vms.h* files are now copied to the lib and
$!                   src directories as config.h.
$!
$ on control_y then goto Common_Exit
$ origdir = f$environment("DEFAULT")
$ proc    = f$environment("PROCEDURE")
$ thisdir = f$parse( proc,,,"DEVICE") + f$parse( proc,,,"DIRECTORY")
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
$ defines = thisdir + "defines.com"
$ if f$search( defines) .eqs. "" 
$ then
$    write sys$output "%CURL-F-DEFFNF, cannot find defines.com procedure"
$    exit %X18290 ! FNF
$ endif
$ set def 'thisdir'
$ cc_qual = "/define=HAVE_CONFIG_H=1/OBJ=OBJDIR:"
$ link_qual = ""
$ if p1 .eqs. "LISTING" then cc_qual = cc_qual + "/LIST/MACHINE"
$ if p1 .eqs. "DEBUG" 
$ then 
$    cc_qual = cc_qual + "/LIST/MACHINE/DEBUG/NOOPT"
$    link_qual = "/DEBUG"
$ endif
$ msg_qual = "/OBJ=OBJDIR:"
$!
$ hpssl   = 0
$ openssl = 0
$ if f$trnlnm( "CURL_BUILD_NOSSL") .eqs. ""
$ then
$    if f$trnlnm( "OPENSSL") .nes. "" 
$    then
$       openssl = 1
$       if ( f$trnlnm( "SSL$INCLUDE") .nes. "") .and. -
           ( f$trnlnm( "CURL_BUILD_NOHPSSL") .eqs. "")
$       then hpssl = 1
$       endif
$    endif
$ endif
$!
$! Put the right main config file in the two source directories for the build.
$!
$ if ( openssl .eq. 1) .or. ( hpssl .eq. 1)
$ then
$    'vo_c' "%CURL-I-BLDSSL, building with SSL support"
$    source_h = "CONFIG-VMS.H_WITH_SSL"
$ else
$    'vo_c' "%CURL-I-BLDNOSSL, building without SSL support"
$    source_h = "CONFIG-VMS.H_WITHOUT_SSL"
$ endif
$!
$! Only do the copy if the source and destination files are different.
$! Put this block into Set NoOn mode so that if the diff command triggers
$! an error while error message reporting is turned off, then it won't 
$! just exit the command procedure mysteriously.
$!
$ set noon
$ set message/nof/noi/nos/not
$ diff/out=nla0: 'source_h' [--.SRC]CONFIG.H
$ status = $status
$ set message/f/i/s/t
$ if ( status .ne. %X006C8009) ! if status is not "no diff"
$ then
$    copy 'source_h' [--.SRC]CONFIG.H
$    purge/nolog [--.SRC]CONFIG.H
$ endif
$ set message/nof/noi/nos/not
$ diff/out=nla0: 'source_h' [--.LIB]CONFIG.H
$ status = $status
$ set message/f/i/s/t
$ if ( status .ne. %X006C8009) ! if status is not "no diff"
$ then
$    copy 'source_h' [--.LIB]CONFIG.H
$    purge/nolog [--.LIB]CONFIG.H
$ endif
$ on control_y then goto Common_Exit
$!
$ call build "[--.lib]" "*.c" "objdir:curllib.olb"
$ call build "[--.src]" "*.c" "objdir:curlsrc.olb"
$ call build "[--.src]" "*.msg" "objdir:curlsrc.olb"
$ if ( openssl .eq. 1) .and. ( hpssl .eq. 0)
$ then
$    'vo_l' "%CURL-I-LINK_OSSL, linking with OpenSSL"
$    link 'link_qual'/exe=exedir:curl.exe -
          objdir:curlsrc/lib/include=(main,curlmsg),-
          objdir:curllib/lib, libssl/lib, libcrypto/lib
$ endif
$ if ( openssl .eq. 1) .and. ( hpssl .eq. 1)
$ then
$    'vo_l' "%CURL-I-LINK_HPSSL, linking with hp SSL option"
$    optfile = "[]hpssl_" + f$getsyi("ARCH_NAME") + ".opt/opt"
$    link 'link_qual'/exe=exedir:curl.exe -
          objdir:curlsrc/lib/include=(main,curlmsg),-
          objdir:curllib/lib, 'optfile'
$ endif
$ if ( openssl .eq. 0) .and. ( hpssl .eq. 0)
$ then
$    'vo_l' "%CURL-I-LINK_NOSSL, linking without SSL support"
$    link 'link_qual'/exe=exedir:curl.exe -
          objdir:curlsrc/lib/include=(main,curlmsg),-
          objdir:curllib/lib
$ endif
$!
$ goto Common_Exit
$!
$! Subroutine to build everything with a filetype passed in via P2 in 
$! the directory passed in via P1 and put it in the object library named 
$! via P3
$!
$build:   subroutine
$ on control_y then exit 2
$ set noon
$   set default 'p1'
$   search = p2
$   reset = f$search("reset")
$   if f$search( p3) .eqs. ""
$   then
$      LIB/CREATE/OBJECT 'p3'
$   endif
$   reset = f$search("reset",1)
$Loop:
$   file = f$search(search,1)
$   if file .eqs. "" then goto EndLoop
$      objfile = f$parse("objdir:.OBJ;",file)
$      obj = f$search( objfile, 2)
$      if (obj .nes. "")
$      then
$         if (f$cvtime(f$file(file,"rdt")) .gts. f$cvtime(f$file(obj,"rdt")))
$         then
$            call compile 'file'
$            if .not. $status then exit $status
$            lib/object 'p3' 'objfile'
$         else
$            'vo_o' "%CURL-I-OBJUTD, ", objfile, " is up to date"
$         endif
$      else
$         'vo_o' "%CURL-I-OBJDNE, ", file, " does not exist"
$         call compile 'file'
$         if .not. $status then exit $status
$         lib/object 'p3' 'objfile'
$      endif
$   goto Loop
$EndLoop:
$   !purge
$   set def 'origdir'
$   endsubroutine   ! Build
$!
$! Based on the file TYPE, do the right compile command.  
$! Only C and MSG supported.
$!
$compile:   subroutine
$   on control_y then exit 2
$   set noon
$   file = p1
$   qual = p2+p3+p4+p5+p6+p7+p8
$   typ = f$parse(file,,,"TYPE") - "."
$   cmd_c = "CC "+cc_qual
$   cmd_msg = "MESSAGE "+msg_qual
$   x = cmd_'typ'
$   'vo_c' x," ",file
$   'x' 'file'
$   ENDSUBROUTINE   ! Compile
$!
$Common_Exit:
$   set default 'origdir'
$   exit
