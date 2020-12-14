#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

LIB_VAUTH_CFILES = vauth/cleartext.c vauth/cram.c vauth/digest.c             \
  vauth/digest_sspi.c vauth/krb5_gssapi.c vauth/krb5_sspi.c vauth/ntlm.c     \
  vauth/ntlm_sspi.c vauth/oauth2.c vauth/spnego_gssapi.c vauth/spnego_sspi.c \
  vauth/vauth.c

LIB_VAUTH_HFILES = vauth/digest.h vauth/ntlm.h vauth/vauth.h

LIB_VTLS_CFILES = vtls/bearssl.c vtls/gskit.c vtls/gtls.c vtls/keylog.c  \
  vtls/mbedtls.c vtls/mbedtls_threadlock.c vtls/mesalink.c vtls/nss.c    \
  vtls/openssl.c vtls/schannel.c vtls/schannel_verify.c vtls/sectransp.c \
  vtls/vtls.c vtls/wolfssl.c

LIB_VTLS_HFILES = vtls/bearssl.h vtls/gskit.h vtls/gtls.h vtls/keylog.h      \
  vtls/mbedtls.h vtls/mbedtls_threadlock.h vtls/mesalink.h vtls/nssg.h       \
  vtls/openssl.h vtls/schannel.h vtls/sectransp.h vtls/vtls.h vtls/wolfssl.h

LIB_VQUIC_CFILES = vquic/ngtcp2.c vquic/quiche.c vquic/vquic.c

LIB_VQUIC_HFILES = vquic/ngtcp2.h vquic/quiche.h vquic/vquic.h

LIB_VSSH_CFILES = vssh/libssh.c vssh/libssh2.c vssh/wolfssh.c

LIB_VSSH_HFILES = vssh/ssh.h

LIB_CFILES =         \
  altsvc.c           \
  amigaos.c          \
  asyn-ares.c        \
  asyn-thread.c      \
  base64.c           \
  c-hyper.c          \
  conncache.c        \
  connect.c          \
  content_encoding.c \
  cookie.c           \
  curl_addrinfo.c    \
  curl_ctype.c       \
  curl_des.c         \
  curl_endian.c      \
  curl_fnmatch.c     \
  curl_get_line.c    \
  curl_gethostname.c \
  curl_gssapi.c      \
  curl_memrchr.c     \
  curl_multibyte.c   \
  curl_ntlm_core.c   \
  curl_ntlm_wb.c     \
  curl_path.c        \
  curl_range.c       \
  curl_rtmp.c        \
  curl_sasl.c        \
  curl_sspi.c        \
  curl_threads.c     \
  dict.c             \
  doh.c              \
  dotdot.c           \
  dynbuf.c           \
  easy.c             \
  easygetopt.c       \
  easyoptions.c      \
  escape.c           \
  file.c             \
  fileinfo.c         \
  formdata.c         \
  ftp.c              \
  ftplistparser.c    \
  getenv.c           \
  getinfo.c          \
  gopher.c           \
  hash.c             \
  hmac.c             \
  hostasyn.c         \
  hostcheck.c        \
  hostip.c           \
  hostip4.c          \
  hostip6.c          \
  hostsyn.c          \
  hsts.c             \
  http.c             \
  http2.c            \
  http_chunks.c      \
  http_digest.c      \
  http_negotiate.c   \
  http_ntlm.c        \
  http_proxy.c       \
  idn_win32.c        \
  if2ip.c            \
  imap.c             \
  inet_ntop.c        \
  inet_pton.c        \
  krb5.c             \
  ldap.c             \
  llist.c            \
  md4.c              \
  md5.c              \
  memdebug.c         \
  mime.c             \
  mprintf.c          \
  mqtt.c             \
  multi.c            \
  netrc.c            \
  non-ascii.c        \
  nonblock.c         \
  openldap.c         \
  parsedate.c        \
  pingpong.c         \
  pop3.c             \
  progress.c         \
  psl.c              \
  rand.c             \
  rename.c           \
  rtsp.c             \
  select.c           \
  sendf.c            \
  setopt.c           \
  sha256.c           \
  share.c            \
  slist.c            \
  smb.c              \
  smtp.c             \
  socketpair.c       \
  socks.c            \
  socks_gssapi.c     \
  socks_sspi.c       \
  speedcheck.c       \
  splay.c            \
  strcase.c          \
  strdup.c           \
  strerror.c         \
  strtok.c           \
  strtoofft.c        \
  system_win32.c     \
  telnet.c           \
  tftp.c             \
  timeval.c          \
  transfer.c         \
  url.c              \
  urlapi.c           \
  version.c          \
  version_win32.c    \
  warnless.c         \
  wildcard.c         \
  x509asn1.c

LIB_HFILES =         \
  altsvc.h           \
  amigaos.h          \
  arpa_telnet.h      \
  asyn.h             \
  c-hyper.h          \
  conncache.h        \
  connect.h          \
  content_encoding.h \
  cookie.h           \
  curl_addrinfo.h    \
  curl_base64.h      \
  curl_ctype.h       \
  curl_des.h         \
  curl_endian.h      \
  curl_fnmatch.h     \
  curl_get_line.h    \
  curl_gethostname.h \
  curl_gssapi.h      \
  curl_hmac.h        \
  curl_krb5.h        \
  curl_ldap.h        \
  curl_md4.h         \
  curl_md5.h         \
  curl_memory.h      \
  curl_memrchr.h     \
  curl_multibyte.h   \
  curl_ntlm_core.h   \
  curl_ntlm_wb.h     \
  curl_path.h        \
  curl_printf.h      \
  curl_range.h       \
  curl_rtmp.h        \
  curl_sasl.h        \
  curl_setup.h       \
  curl_setup_once.h  \
  curl_sha256.h      \
  curl_sspi.h        \
  curl_threads.h     \
  curlx.h            \
  dict.h             \
  doh.h              \
  dotdot.h           \
  dynbuf.h           \
  easyif.h           \
  easyoptions.h      \
  escape.h           \
  file.h             \
  fileinfo.h         \
  formdata.h         \
  ftp.h              \
  ftplistparser.h    \
  getinfo.h          \
  gopher.h           \
  hash.h             \
  hostcheck.h        \
  hostip.h           \
  hsts.h             \
  http.h             \
  http2.h            \
  http_chunks.h      \
  http_digest.h      \
  http_negotiate.h   \
  http_ntlm.h        \
  http_proxy.h       \
  if2ip.h            \
  imap.h             \
  inet_ntop.h        \
  inet_pton.h        \
  llist.h            \
  memdebug.h         \
  mime.h             \
  mqtt.h             \
  multihandle.h      \
  multiif.h          \
  netrc.h            \
  non-ascii.h        \
  nonblock.h         \
  parsedate.h        \
  pingpong.h         \
  pop3.h             \
  progress.h         \
  psl.h              \
  quic.h             \
  rand.h             \
  rename.h           \
  rtsp.h             \
  select.h           \
  sendf.h            \
  setopt.h           \
  setup-vms.h        \
  share.h            \
  sigpipe.h          \
  slist.h            \
  smb.h              \
  smtp.h             \
  sockaddr.h         \
  socketpair.h       \
  socks.h            \
  speedcheck.h       \
  splay.h            \
  strcase.h          \
  strdup.h           \
  strerror.h         \
  strtok.h           \
  strtoofft.h        \
  system_win32.h     \
  telnet.h           \
  tftp.h             \
  timeval.h          \
  transfer.h         \
  url.h              \
  urlapi-int.h       \
  urldata.h          \
  version_win32.h    \
  warnless.h         \
  wildcard.h         \
  x509asn1.h

LIB_RCFILES = libcurl.rc

CSOURCES = $(LIB_CFILES) $(LIB_VAUTH_CFILES) $(LIB_VTLS_CFILES) \
  $(LIB_VQUIC_CFILES) $(LIB_VSSH_CFILES)
HHEADERS = $(LIB_HFILES) $(LIB_VAUTH_HFILES) $(LIB_VTLS_HFILES) \
  $(LIB_VQUIC_HFILES) $(LIB_VSSH_HFILES)
