$! DEFINES.COM
$! Define where to look for the curl include directory, where to put the 
$! exes and objects, and the openssl stuff.  If you have hp's SSL product 
$! installed you won't need these openssl, libssl and libcrypto defines.
$!
$! Be cautioned, though.  If you build using these defines at the process
$! level and then try to build against hp's SSL product, you will need to 
$! deassign the openssl logical at the process level or the link will most
$! probably fail, or define CURL_BUILD_NOHPSSL to anything.
$!
$!  8-FEB-2005, MSK, changed the openssl, libssl and libcrypto defines
$!                   to not override previously defined logicals.
$!
$ proc = f$environment( "PROCEDURE")
$ thisdev = f$parse( proc,,,"DEVICE")
$ thisdir = f$parse( proc,,,"DIRECTORY") - ".PACKAGES.VMS]"
$ newdir  = f$parse( proc,,,"DEVICE") + f$parse( proc,,,"DIRECTORY")
$ exedir  = newdir - "]"
$!
$ arch = f$getsyi("ARCH_TYPE")
$ if ( arch .eq. 1) 
$ then
$    exedir = exedir + ".VAX]"
$    ssldir = "VAX"
$ else
$    if ( arch .eq. 2) 
$    then
$       exedir = exedir + ".AXP]"
$       ssldir = "AXP"
$    else
$       exedir = exedir + ".IA64]"
$       ssldir = "IA64"
$    endif
$ endif
$ def/nolog exedir 'exedir'
$ def/nolog objdir 'exedir'
$ def/nolog lisdir 'exedir'
$!
$ def/nolog curl      'THISDEV''THISDIR'.INCLUDE.CURL]
$ def/nolog libsrc    'THISDEV''THISDIR'.LIB]
$ def/nolog curlsrc   'THISDEV''THISDIR'.SRC]
$!
$! If you're going to build against an OpenSSL dist, you'll want to define
$! the following logicals to point to the dist location.
$! 
$ if ( f$trnlnm( "openssl") .eqs. "") 
$ then
$    def/nolog openssl   'THISDEV'[OPENSSL.OPENSSL-0_9_7E.INCLUDE.OPENSSL]
$ endif
$ if ( f$trnlnm( "libssl") .eqs. "") 
$ then
$    def/nolog libssl    'THISDEV'[OPENSSL.OPENSSL-0_9_7E.'ssldir'.EXE.SSL]LIBSSL.OLB
$ endif
$ if ( f$trnlnm( "libcrypto") .eqs. "") 
$ then
$    def/nolog libcrypto 'THISDEV'[OPENSSL.OPENSSL-0_9_7E.'ssldir'.EXE.CRYPTO]LIBCRYPTO.OLB
$ endif
$! 
$! If you have hp's SSL product installed, and you still want to build
$! against an OpenSSL distribution, you'll need to define the following
$! logical.  The CURL_BUILD_NOHPSSL logical is used by BUILD_VMS.COM.
$!
$ def/nolog CURL_BUILD_NOHPSSL true
$!
$! The curl code has some mixed up includes where a user include is done
$! with <> and a system include is done with "".  Define a broader include
$! path to make the compile work "right".
$!
$ def/nolog decc$system_include libsrc:,curlsrc:
$!
$! The build_vms.com checks to see if the curl_defines_done logical is 
$! defined.  If it isn't it will invoke this procedure.  If it is, and 
$! you change something in here, you'll have to run the procedure yourself.
$!
$ def/nolog curl_defines_done true
$!
$ exit
