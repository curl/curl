#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

LIB_VAUTH_CFILES = vauth/vauth.c vauth/cleartext.c vauth/cram.c         \
  vauth/digest.c vauth/digest_sspi.c vauth/krb5_gssapi.c                \
  vauth/krb5_sspi.c vauth/ntlm.c vauth/ntlm_sspi.c vauth/oauth2.c       \
  vauth/spnego_gssapi.c vauth/spnego_sspi.c

LIB_VAUTH_HFILES = vauth/vauth.h vauth/digest.h vauth/ntlm.h

LIB_VTLS_CFILES = vtls/openssl.c vtls/gtls.c vtls/vtls.c vtls/nss.c     \
  vtls/polarssl.c vtls/polarssl_threadlock.c vtls/axtls.c               \
  vtls/cyassl.c vtls/schannel.c vtls/darwinssl.c vtls/gskit.c           \
  vtls/mbedtls.c

LIB_VTLS_HFILES = vtls/openssl.h vtls/vtls.h vtls/gtls.h                \
  vtls/nssg.h vtls/polarssl.h vtls/polarssl_threadlock.h vtls/axtls.h   \
  vtls/cyassl.h vtls/schannel.h vtls/darwinssl.h vtls/gskit.h           \
  vtls/mbedtls.h

LIB_CFILES = file.c timeval.c base64.c hostip.c progress.c formdata.c   \
  cookie.c http.c sendf.c ftp.c url.c dict.c if2ip.c speedcheck.c       \
  ldap.c version.c getenv.c escape.c mprintf.c telnet.c netrc.c         \
  getinfo.c transfer.c strcase.c easy.c security.c curl_fnmatch.c       \
  fileinfo.c ftplistparser.c wildcard.c krb5.c memdebug.c http_chunks.c \
  strtok.c connect.c llist.c hash.c multi.c content_encoding.c share.c  \
  http_digest.c md4.c md5.c http_negotiate.c inet_pton.c strtoofft.c    \
  strerror.c amigaos.c hostasyn.c hostip4.c hostip6.c hostsyn.c         \
  inet_ntop.c parsedate.c select.c tftp.c splay.c strdup.c socks.c      \
  ssh.c ssh-libssh.c curl_addrinfo.c socks_gssapi.c socks_sspi.c        \
  curl_sspi.c slist.c nonblock.c curl_memrchr.c imap.c pop3.c smtp.c    \
  pingpong.c rtsp.c curl_threads.c warnless.c hmac.c curl_rtmp.c        \
  openldap.c curl_gethostname.c gopher.c idn_win32.c                    \
  http_proxy.c non-ascii.c asyn-ares.c asyn-thread.c curl_gssapi.c      \
  http_ntlm.c curl_ntlm_wb.c curl_ntlm_core.c curl_sasl.c rand.c        \
  curl_multibyte.c hostcheck.c conncache.c pipeline.c dotdot.c          \
  x509asn1.c http2.c smb.c curl_endian.c curl_des.c system_win32.c      \
  mime.c sha256.c setopt.c curl_path.c curl_ctype.c curl_range.c

LIB_HFILES = arpa_telnet.h netrc.h file.h timeval.h hostip.h progress.h \
  formdata.h cookie.h http.h sendf.h ftp.h url.h dict.h if2ip.h         \
  speedcheck.h urldata.h curl_ldap.h escape.h telnet.h getinfo.h        \
  strcase.h curl_sec.h memdebug.h http_chunks.h curl_fnmatch.h          \
  wildcard.h fileinfo.h ftplistparser.h strtok.h connect.h llist.h      \
  hash.h content_encoding.h share.h curl_md4.h curl_md5.h http_digest.h \
  http_negotiate.h inet_pton.h amigaos.h strtoofft.h strerror.h         \
  inet_ntop.h curlx.h curl_memory.h curl_setup.h transfer.h select.h    \
  easyif.h multiif.h parsedate.h tftp.h sockaddr.h splay.h strdup.h     \
  socks.h ssh.h curl_base64.h curl_addrinfo.h curl_sspi.h      \
  slist.h nonblock.h curl_memrchr.h imap.h pop3.h smtp.h pingpong.h     \
  rtsp.h curl_threads.h warnless.h curl_hmac.h curl_rtmp.h              \
  curl_gethostname.h gopher.h http_proxy.h non-ascii.h asyn.h           \
  http_ntlm.h curl_gssapi.h curl_ntlm_wb.h curl_ntlm_core.h             \
  curl_sasl.h curl_multibyte.h hostcheck.h conncache.h                  \
  curl_setup_once.h multihandle.h setup-vms.h pipeline.h dotdot.h       \
  x509asn1.h http2.h sigpipe.h smb.h curl_endian.h curl_des.h           \
  curl_printf.h system_win32.h rand.h mime.h curl_sha256.h setopt.h     \
  curl_path.h curl_ctype.h curl_range.h

LIB_RCFILES = libcurl.rc

CSOURCES = $(LIB_CFILES) $(LIB_VAUTH_CFILES) $(LIB_VTLS_CFILES)
HHEADERS = $(LIB_HFILES) $(LIB_VAUTH_HFILES) $(LIB_VTLS_HFILES)
