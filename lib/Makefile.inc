#*************************************************************************** #
Project # _____ __ .__ # _/ ____\_____/ |_ ____ | |__ # \ __\/ __ \ __\/ ___\| |
\ # | | \ ___/| | \ \___| Y \ # |__| \___ >__| \___ >___| / # \/ \/ \/ # #
Copyright (C) Daniel Stenberg,
<daniel@haxx.se
  >, et al. # # This software is licensed as described in the file COPYING,
  which # you should have received as part of this distribution. The terms # are
  also available at https://curl.se/docs/copyright.html. # # You may opt to use,
  copy, modify, merge, publish, distribute and/or sell # copies of the Software,
  and permit persons to whom the Software is # furnished to do so, under the
  terms of the COPYING file. # # This software is distributed on an "AS IS"
  basis, WITHOUT WARRANTY OF ANY # KIND, either express or implied. # #
  SPDX-License-Identifier: fetch #
  ###########################################################################
  LIB_VAUTH_CFILES = \ vauth/cleartext.c \ vauth/cram.c \ vauth/digest.c \
  vauth/digest_sspi.c \ vauth/gsasl.c \ vauth/krb5_gssapi.c \ vauth/krb5_sspi.c
  \ vauth/ntlm.c \ vauth/ntlm_sspi.c \ vauth/oauth2.c \ vauth/spnego_gssapi.c \
  vauth/spnego_sspi.c \ vauth/vauth.c LIB_VAUTH_HFILES = \ vauth/digest.h \
  vauth/ntlm.h \ vauth/vauth.h LIB_VTLS_CFILES = \ vtls/bearssl.c \
  vtls/cipher_suite.c \ vtls/gtls.c \ vtls/hostcheck.c \ vtls/keylog.c \
  vtls/mbedtls.c \ vtls/mbedtls_threadlock.c \ vtls/openssl.c \ vtls/rustls.c \
  vtls/schannel.c \ vtls/schannel_verify.c \ vtls/sectransp.c \ vtls/vtls.c \
  vtls/vtls_scache.c \ vtls/vtls_spack.c \ vtls/wolfssl.c \ vtls/x509asn1.c
  LIB_VTLS_HFILES = \ vtls/bearssl.h \ vtls/cipher_suite.h \ vtls/gtls.h \
  vtls/hostcheck.h \ vtls/keylog.h \ vtls/mbedtls.h \ vtls/mbedtls_threadlock.h
  \ vtls/openssl.h \ vtls/rustls.h \ vtls/schannel.h \ vtls/schannel_int.h \
  vtls/sectransp.h \ vtls/vtls.h \ vtls/vtls_int.h \ vtls/vtls_scache.h \
  vtls/vtls_spack.h \ vtls/wolfssl.h \ vtls/x509asn1.h LIB_VQUIC_CFILES = \
  vquic/fetch_msh3.c \ vquic/fetch_ngtcp2.c \ vquic/fetch_osslq.c \
  vquic/fetch_quiche.c \ vquic/vquic.c \ vquic/vquic-tls.c LIB_VQUIC_HFILES = \
  vquic/fetch_msh3.h \ vquic/fetch_ngtcp2.h \ vquic/fetch_osslq.h \
  vquic/fetch_quiche.h \ vquic/vquic.h \ vquic/vquic_int.h \ vquic/vquic-tls.h
  LIB_VSSH_CFILES = \ vssh/libssh.c \ vssh/libssh2.c \ vssh/fetch_path.c \
  vssh/wolfssh.c LIB_VSSH_HFILES = \ vssh/fetch_path.h \ vssh/ssh.h LIB_CFILES =
  \ altsvc.c \ amigaos.c \ asyn-ares.c \ asyn-thread.c \ base64.c \ bufq.c \
  bufref.c \ cf-h1-proxy.c \ cf-h2-proxy.c \ cf-haproxy.c \ cf-https-connect.c \
  cf-socket.c \ cfilters.c \ conncache.c \ connect.c \ content_encoding.c \
  cookie.c \ fetch_addrinfo.c \ fetch_des.c \ fetch_endian.c \ fetch_fnmatch.c \
  fetch_get_line.c \ fetch_gethostname.c \ fetch_gssapi.c \ fetch_memrchr.c \
  fetch_multibyte.c \ fetch_ntlm_core.c \ fetch_range.c \ fetch_rtmp.c \
  fetch_sasl.c \ fetch_sha512_256.c \ fetch_sspi.c \ fetch_threads.c \
  fetch_trc.c \ cw-out.c \ dict.c \ dllmain.c \ doh.c \ dynbuf.c \ dynhds.c \
  easy.c \ easygetopt.c \ easyoptions.c \ escape.c \ file.c \ fileinfo.c \
  fopen.c \ formdata.c \ ftp.c \ ftplistparser.c \ getenv.c \ getinfo.c \
  gopher.c \ hash.c \ headers.c \ hmac.c \ hostasyn.c \ hostip.c \ hostip4.c \
  hostip6.c \ hostsyn.c \ hsts.c \ http.c \ http1.c \ http2.c \ http_aws_sigv4.c
  \ http_chunks.c \ http_digest.c \ http_negotiate.c \ http_ntlm.c \
  http_proxy.c \ httpsrr.c \ idn.c \ if2ip.c \ imap.c \ inet_ntop.c \
  inet_pton.c \ krb5.c \ ldap.c \ llist.c \ macos.c \ md4.c \ md5.c \ memdebug.c
  \ mime.c \ mprintf.c \ mqtt.c \ multi.c \ netrc.c \ nonblock.c \ noproxy.c \
  openldap.c \ parsedate.c \ pingpong.c \ pop3.c \ progress.c \ psl.c \ rand.c \
  rename.c \ request.c \ rtsp.c \ select.c \ sendf.c \ setopt.c \ sha256.c \
  share.c \ slist.c \ smb.c \ smtp.c \ socketpair.c \ socks.c \ socks_gssapi.c \
  socks_sspi.c \ speedcheck.c \ splay.c \ strcase.c \ strdup.c \ strerror.c \
  strparse.c \ strtok.c \ strtoofft.c \ system_win32.c \ telnet.c \ tftp.c \
  timediff.c \ timeval.c \ transfer.c \ url.c \ urlapi.c \ version.c \
  version_win32.c \ warnless.c \ ws.c LIB_HFILES = \ altsvc.h \ amigaos.h \
  arpa_telnet.h \ asyn.h \ bufq.h \ bufref.h \ cf-h1-proxy.h \ cf-h2-proxy.h \
  cf-haproxy.h \ cf-https-connect.h \ cf-socket.h \ cfilters.h \ conncache.h \
  connect.h \ content_encoding.h \ cookie.h \ fetch_addrinfo.h \ fetch_base64.h
  \ fetch_ctype.h \ fetch_des.h \ fetch_endian.h \ fetch_fnmatch.h \
  fetch_get_line.h \ fetch_gethostname.h \ fetch_gssapi.h \ fetch_hmac.h \
  fetch_krb5.h \ fetch_ldap.h \ fetch_md4.h \ fetch_md5.h \ fetch_memory.h \
  fetch_memrchr.h \ fetch_multibyte.h \ fetch_ntlm_core.h \ fetch_printf.h \
  fetch_range.h \ fetch_rtmp.h \ fetch_sasl.h \ fetch_setup.h \
  fetch_setup_once.h \ fetch_sha256.h \ fetch_sha512_256.h \ fetch_sspi.h \
  fetch_threads.h \ fetch_trc.h \ fetchx.h \ cw-out.h \ dict.h \ doh.h \
  dynbuf.h \ dynhds.h \ easy_lock.h \ easyif.h \ easyoptions.h \ escape.h \
  file.h \ fileinfo.h \ fopen.h \ formdata.h \ ftp.h \ ftplistparser.h \
  functypes.h \ getinfo.h \ gopher.h \ hash.h \ headers.h \ hostip.h \ hsts.h \
  http.h \ http1.h \ http2.h \ http_aws_sigv4.h \ http_chunks.h \ http_digest.h
  \ http_negotiate.h \ http_ntlm.h \ http_proxy.h \ httpsrr.h \ idn.h \ if2ip.h
  \ imap.h \ inet_ntop.h \ inet_pton.h \ llist.h \ macos.h \ memdebug.h \ mime.h
  \ mqtt.h \ multihandle.h \ multiif.h \ netrc.h \ nonblock.h \ noproxy.h \
  parsedate.h \ pingpong.h \ pop3.h \ progress.h \ psl.h \ rand.h \ rename.h \
  request.h \ rtsp.h \ select.h \ sendf.h \ setopt.h \ setup-os400.h \
  setup-vms.h \ setup-win32.h \ share.h \ sigpipe.h \ slist.h \ smb.h \ smtp.h \
  sockaddr.h \ socketpair.h \ socks.h \ speedcheck.h \ splay.h \ strcase.h \
  strdup.h \ strerror.h \ strparse.h \ strtok.h \ strtoofft.h \ system_win32.h \
  telnet.h \ tftp.h \ timediff.h \ timeval.h \ transfer.h \ url.h \ urlapi-int.h
  \ urldata.h \ version_win32.h \ warnless.h \ ws.h LIB_RCFILES = libfetch.rc
  CSOURCES = $(LIB_CFILES) $(LIB_VAUTH_CFILES) $(LIB_VTLS_CFILES) \
  $(LIB_VQUIC_CFILES) $(LIB_VSSH_CFILES) HHEADERS = $(LIB_HFILES)
  $(LIB_VAUTH_HFILES) $(LIB_VTLS_HFILES) \ $(LIB_VQUIC_HFILES)
  $(LIB_VSSH_HFILES)
</daniel@haxx.se>
