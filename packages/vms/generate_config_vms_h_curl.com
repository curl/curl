$! File: GENERATE_CONFIG_H_CURL.COM
$!
$! $Id$
$!
$! Curl like most open source products uses a variant of a config.h file.
$! Depending on the curl version, this could be config.h or curl_config.h.
$!
$! For GNV based builds, the configure script is run and that produces
$! a [curl_]config.h file.  Configure scripts on VMS generally do not
$! know how to do everything, so there is also a [-.lib]config-vms.h file
$! that has VMS specific code that compensates for bugs in some of the
$! VMS shared images.
$!
$! This generates a [curl_]config.h file and also a config_vms.h file,
$! which is used to supplement that file.  Note that the config_vms.h file
$! and the [.lib]config-vms.h file do two different tasks and that the
$! filenames are slightly different.
$!
$!
$! Copyright 2013 - 2021, John Malmberg
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
$! 06-Jan-2013	J. Malmberg
$!
$!=========================================================================
$!
$! Allow arguments to be grouped together with comma or separated by spaces
$! Do no know if we will need more than 8.
$args = "," + p1 + "," + p2 + "," + p3 + "," + p4 + ","
$args = args + p5 + "," + p6 + "," + p7 + "," + p8 + ","
$!
$! Provide lower case version to simplify parsing.
$args_lower = f$edit(args, "LOWERCASE")
$!
$args_len = f$length(args)
$!
$if (f$getsyi("HW_MODEL") .lt. 1024)
$then
$   arch_name = "VAX"
$else
$   arch_name = ""
$   arch_name = arch_name + f$edit(f$getsyi("ARCH_NAME"), "UPCASE")
$   if (arch_name .eqs. "") then arch_name = "UNK"
$endif
$!
$!
$nossl = 0
$nohpssl = 1
$hpssl = 0
$libidn = 0
$libssh2 = 0
$noldap = 0
$nozlib = 0
$nokerberos = 0
$!
$! First check to see if SSL is disabled.
$!---------------------------------------
$if f$locate(",nossl,", args_lower) .lt. args_len then nossl = 1
$if .not. nossl
$then
$!
$!  ssl$* logicals means HP ssl is present
$!----------------------------------------
$   if f$trnlnm("ssl$root") .nes. ""
$   then
$	nohpssl = 0
$	hpssl = 1
$   endif
$!
$!  HP defines OPENSSL as SSL$INCLUDE as a convenience for linking.
$!  As it is a violation of VMS standards for this to be provided,
$!  some sites may have removed it, but if present, assume that
$!  it indicates which OpenSSL to use.
$!------------------------------------
$   openssl_lnm = f$trnlnm("OPENSSL")
$   if (openssl_lnm .nes. "SYS$INCLUDE")
$   then
$!	Non HP SSL is installed, default to use it.
$	nohpssl = 1
$	hpssl = 0
$   endif
$!
$!  Now check to see if hpssl has been specifically disabled
$!----------------------------------------------------------
$   if f$locate(",nohpssl,", args_lower) .lt. args_len
$   then
$	nohpssl = 1
$	hpssl = 0
$   endif
$!
$!  Finally check to see if hp ssl has been specifically included.
$!----------------------------------------------------------------
$   if f$locate(",nohpssl,", args_lower) .lt. args_len
$   then
$	nohpssl = 1
$	hpssl = 0
$   endif
$endif
$!
$! Did someone port LIBIDN in the GNV compatible way?
$!------------------------------------------------------
$if f$trnlnm("GNV$LIBIDNSHR") .nes. ""
$then
$   write sys$output "NOTICE:  A LIBIDN port has been detected."
$   write sys$output " This port of curl for VMS has not been tested with it."
$   if f$locate(",libidn,", args_lower) .lt. args_len
$   then
$	libidn = 1
$   endif
$   if .not. libidn
$   then
$	write sys$output " LIBIDN support is not enabled."
$	write sys$output "Run with the ""libidn"" parameter to attempt to use."
$   else
$	write sys$output " Untested LIBIDN support requested."
$   endif
$endif
$!
$! Did someone port LIBSSH2 in the GNV compatible way?
$!------------------------------------------------------
$if f$trnlnm("GNV$LIBSSH2SHR") .nes. ""
$then
$   write sys$output "NOTICE:  A LIBSSH2 port has been detected."
$   write sys$output " This port of curl for VMS has not been tested with it."
$   if f$locate(",libssh2,", args_lower) .lt. args_len
$   then
$	libssh2 = 1
$   endif
$   if .not. libssh2
$   then
$	write sys$output " LIBSSH2 support is not enabled."
$	write sys$output "Run with the ""libssh2"" parameter to attempt to use."
$   else
$	write sys$output " Untested LIBSSH2 support requested."
$   endif
$endif
$!
$! LDAP suppressed?
$if f$locate(",noldap,", args_lower) .lt. args_len
$then
$   noldap = 1
$endif
$if f$search("SYS$SHARE:LDAP$SHR.EXE") .eqs. ""
$then
$   noldap = 1
$endif
$!
$if f$locate(",nokerberos,", args_lower) .lt. args_len then nokerberos = 1
$if .not. nokerberos
$then
$!  If kerberos is installed: sys$share:gss$rtl.exe exists.
$   if f$search("sys$shsare:gss$rtl.exe") .eqs. ""
$   then
$	nokerberos = 1
$   endif
$endif
$!
$!
$! Is GNV compatible LIBZ present?
$!------------------------------------------------------
$if f$trnlnm("GNV$LIBZSHR") .nes. ""
$then
$   if f$locate(",nozlib,", args_lower) .lt. args_len
$   then
$	nozlib = 1
$   endif
$!   if .not. nozlib
$!   then
$!	write sys$output " GNV$LIBZSHR support is enabled."
$!   else
$!	write sys$output " GNV$LIBZSHR support is disabled by nozlib."
$!   endif
$else
$   nozlib = 1
$endif
$!
$!
$! Start the configuration file.
$! Need to do a create and then an append to make the file have the
$! typical file attributes of a VMS text file.
$create sys$disk:[curl.lib]config_vms.h
$open/append cvh sys$disk:[curl.lib]config_vms.h
$!
$! Write the defines to prevent multiple includes.
$! These are probably not needed in this case,
$! but are best practice to put on all header files.
$write cvh "#ifndef __CONFIG_VMS_H__"
$write cvh "#define __CONFIG_VMS_H__"
$write cvh ""
$write cvh "/* Define cpu-machine-OS */"
$!
$! Curl uses an OS macro to set the build environment.
$!----------------------------------------------------
$! Now the DCL builds usually say xxx-HP-VMS and configure scripts
$! may put DEC or COMPAQ or HP for the middle part.
$!
$write cvh "#if defined(__alpha)"
$write cvh "#define OS ""ALPHA-HP-VMS"""
$write cvh "#elif defined(__vax)"
$write cvh "#define OS ""VAX-HP-VMS"""
$write cvh "#elif defined(__ia64)"
$write cvh "#define OS ""IA64-HP-VMS""
$write cvh "#else"
$write cvh "#define OS ""UNKNOWN-HP-VMS""
$write cvh "#endif"
$write cvh ""
$!
$! We are now setting this on the GNV build, so also do this
$! for compatibility.
$write cvh "/* Location of default ca path */"
$write cvh "#define curl_ca_path ""gnv$curl_ca_path"""
$!
$! NTLM_WB_ENABLED requires fork() but configure does not know this
$! We have to disable this in the configure command line.
$! config_h.com finds that configure defaults to it being enabled so
$! reports it.  So we need to turn it off here.
$!
$write cvh "#ifdef NTLM_WB_ENABLED"
$write cvh "#undef NTLM_WB_ENABLED"
$write cvh "#endif"
$!
$! The config_h.com finds a bunch of default disable commands in
$! configure and will incorrectly disable these options.  The config_h.com
$! is a generic procedure and it would break more things to try to fix it
$! to special case it for curl.  So we will fix it here.
$!
$! We do them all here, even the ones that config_h.com currently gets correct.
$!
$write cvh "#ifdef CURL_DISABLE_COOKIES"
$write cvh "#undef CURL_DISABLE_COOKIES"
$write cvh "#endif"
$write cvh "#ifdef CURL_DISABLE_CRYPTO_AUTH"
$write cvh "#undef CURL_DISABLE_CRYPTO_AUTH"
$write cvh "#endif"
$write cvh "#ifdef CURL_DISABLE_DICT"
$write cvh "#undef CURL_DISABLE_DICT"
$write cvh "#endif"
$write cvh "#ifdef CURL_DISABLE_FILE"
$write cvh "#undef CURL_DISABLE_FILE"
$write cvh "#endif"
$write cvh "#ifdef CURL_DISABLE_FTP"
$write cvh "#undef CURL_DISABLE_FTP"
$write cvh "#endif"
$write cvh "#ifdef CURL_DISABLE_GOPHER"
$write cvh "#undef CURL_DISABLE_GOPHER"
$write cvh "#endif"
$write cvh "#ifdef CURL_DISABLE_HTTP"
$write cvh "#undef CURL_DISABLE_HTTP"
$write cvh "#endif"
$write cvh "#ifdef CURL_DISABLE_IMAP"
$write cvh "#undef CURL_DISABLE_IMAP"
$write cvh "#endif"
$if .not. noldap
$then
$   write cvh "#ifdef CURL_DISABLE_LDAP"
$   write cvh "#undef CURL_DISABLE_LDAP"
$   write cvh "#endif"
$   if .not. nossl
$   then
$	write cvh "#ifdef CURL_DISABLE_LDAPS"
$	write cvh "#undef CURL_DISABLE_LDAPS"
$	write cvh "#endif"
$   endif
$endif
$write cvh "#ifdef CURL_DISABLE_LIBCURL_OPTION"
$write cvh "#undef CURL_DISABLE_LIBCURL_OPTION"
$write cvh "#endif"
$write cvh "#ifndef __VAX"
$write cvh "#ifdef CURL_DISABLE_NTLM"
$write cvh "#undef CURL_DISABLE_NTLM"
$write cvh "#endif"
$write cvh "#else"
$! NTLM needs long long or int64 support, missing from DECC C.
$write cvh "#ifdef __DECC
$write cvh "#ifndef CURL_DISABLE_NTLM"
$write cvh "#define CURL_DISABLE_NTLM 1"
$write cvh "#endif"
$write cvh "#endif"
$write cvh "#endif"
$write cvh "#ifdef CURL_DISABLE_POP3"
$write cvh "#undef CURL_DISABLE_POP3"
$write cvh "#endif"
$write cvh "#ifdef CURL_DISABLE_PROXY"
$write cvh "#undef CURL_DISABLE_PROXY"
$write cvh "#endif"
$write cvh "#ifdef CURL_DISABLE_RTSP"
$write cvh "#undef CURL_DISABLE_RTSP"
$write cvh "#endif"
$write cvh "#ifdef CURL_DISABLE_SMTP"
$write cvh "#undef CURL_DISABLE_SMTP"
$write cvh "#endif"
$write cvh "#ifdef CURL_DISABLE_TELNET"
$write cvh "#undef CURL_DISABLE_TELNET"
$write cvh "#endif"
$write cvh "#ifdef CURL_DISABLE_TFTP"
$write cvh "#undef CURL_DISABLE_TFTP"
$write cvh "#endif"
$write cvh "#ifdef CURL_DISABLE_POP3"
$write cvh "#undef CURL_DISABLE_POP3"
$write cvh "#endif"
$if .not. nossl
$then
$   write cvh "#ifdef CURL_DISABLE_TLS_SRP"
$   write cvh "#undef CURL_DISABLE_TLS_SRP"
$   write cvh "#endif"
$!
$endif
$write cvh "#ifdef CURL_DISABLE_VERBOSE_STRINGS"
$write cvh "#undef CURL_DISABLE_VERBOSE_STRINGS"
$write cvh "#endif"
$!
$! configure defaults to USE_*, a real configure on VMS chooses different.
$write cvh "#ifdef USE_ARES"
$write cvh "#undef USE_ARES"
$write cvh "#endif"
$write cvh "#ifdef USE_WOLFSSL"
$write cvh "#undef USE_WOLFSSL"
$write cvh "#endif"
$write cvh "#ifdef USE_GNUTLS"
$write cvh "#undef USE_GNUTLS"
$write cvh "#endif"
$write cvh "#ifdef USE_LIBRTMP"
$write cvh "#undef USE_LIBRTMP"
$write cvh "#endif"
$write cvh "#ifdef USE_MANUAL"
$write cvh "#undef USE_MANUAL"
$write cvh "#endif"
$write cvh "#ifdef USE_NGHTTP2"
$write cvh "#undef USE_NGHTTP2"
$write cvh "#endif"
$write cvh "#ifdef USE_NSS"
$write cvh "#undef USE_NSS"
$write cvh "#endif"
$write cvh "#ifdef USE_OPENLDAP"
$write cvh "#undef USE_OPENLDAP"
$write cvh "#endif"
$write cvh "#ifdef USE_THREADS_POSIX"
$write cvh "#undef USE_THREADS_POSIX"
$write cvh "#endif"
$write cvh "#ifdef USE_TLS_SRP"
$write cvh "#undef USE_TLS_SRP"
$write cvh "#endif"
$write cvh "#ifdef USE_UNIX_SOCKETS"
$write cvh "#undef USE_UNIX_SOCKETS"
$write cvh "#endif"
$!
$write cvh "#ifndef HAVE_OLD_GSSMIT"
$write cvh "#define gss_nt_service_name GSS_C_NT_HOSTBASED_SERVICE"
$write cvh "#endif"
$!
$!
$! Note:
$! The CURL_EXTERN_SYMBOL is used for platforms that need the compiler
$! to know about universal symbols.  VMS does not need this support so
$! we do not set it here.
$!
$!
$! I can not figure out where the C compiler is finding the ALLOCA.H file
$! in the text libraries, so CONFIG_H.COM can not find it either.
$! Usually the header file name is the module name in the text library.
$! It does not appear to hurt anything to not find header file, so we
$! are not overriding it here.
$!
$!
$! Check to see if OpenSSL is present.
$!----------------------------------
$ssl_include = f$trnlnm("OPENSSL")
$if ssl_include .eqs. ""
$then
$    ssl_include = f$trnlnm("ssl$include")
$endif
$if ssl_include .eqs. "" then nossl = 1
$!
$if .not. nossl
$then
$!
$   write cvh "#ifndef USE_OPENSSL"
$   write cvh "#define USE_OPENSSL 1"
$   write cvh "#endif"
$   if arch_name .eqs. "VAX"
$   then
$       old_mes = f$environment("message")
$       set message/notext/nofaci/noseve/noident
$       search/output=nla0: ssl$include:*.h CONF_MFLAGS_IGNORE_MISSING_FILE
$       status = $severity
$       set message'old_mes'
$       if status .nes. "1"
$       then
$           write cvh "#define VMS_OLD_SSL 1"
$       endif
$   endif
$endif
$!
$!
$! LibIDN not ported to VMS at this time.
$! This is for international domain name support.
$! Allow explicit experimentation.
$if libidn
$then
$   write cvh "#define HAVE_IDNA_STRERROR 1"
$   write cvh "#define HAVE_IDNA_FREE 1"
$   write cvh "#define HAVE_IDNA_FREE_H 1"
$   write cvh "#define HAVE_LIBIDN 1"
$else
$   write cvh "#ifdef HAVE_LIBIDN"
$   write cvh "#undef HAVE_LIBIDN"
$   write cvh "#endif"
$endif
$!
$!
$! LibSSH2 not ported to VMS at this time.
$! Allow explicit experimentation.
$if libssh2
$then
$   write cvh "#define HAVE_LIBSSH2_EXIT 1"
$   write cvh "#define HAVE_LIBSSH2_H 1"
$   write cvh "#define HAVE_LIBSSH2_INIT 1"
$   write cvh "#define HAVE_LIBSSH2_SCP_SEND64 1"
$   write cvh "#define HAVE_LIBSSH2_SESSION_HANDSHAKE 1"
$   write cvh "#define HAVE_LIBSSH2_VERSION 1
$   write cvh "#define HAVE_LIBSSH2 1
$!
$   write cvh "#ifndef USE_LIBSSH2"
$   write cvh "#define USE_LIBSSH2 1"
$   write cvh "#endif"
$else
$   write cvh "#ifdef USE_LIBSSH2"
$   write cvh "#undef USE_LIBSSH2"
$   write cvh "#endif"
$endif
$!
$!
$!
$if .not. nozlib
$then
$   write cvh "#define HAVE_LIBZ 1"
$   write cvh "#define HAVE_ZLIB_H 1"
$endif
$!
$!
$! Suppress a message in curl_gssapi.c compile.
$write cvh "#pragma message disable notconstqual"
$!
$! Close out the file
$!
$write cvh ""
$write cvh "#endif /* __CONFIG_VMS_H__ */"
$close cvh
$!
$all_exit:
$exit
