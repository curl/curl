# ./lib/Makefile.inc
# Using the backslash as line continuation character might be problematic
# with some make flavours, as Watcom's wmake showed us already. If we
# ever want to change this in a portable manner then we should consider
# this idea (posted to the libcurl list by Adam Kellas):
# CSRC1 = file1.c file2.c file3.c
# CSRC2 = file4.c file5.c file6.c
# CSOURCES = $(CSRC1) $(CSRC2)

CSOURCES = file.c timeval.c base64.c hostip.c progress.c formdata.c	\
  cookie.c http.c sendf.c ftp.c url.c dict.c if2ip.c speedcheck.c	\
  ldap.c ssluse.c version.c getenv.c escape.c mprintf.c telnet.c	\
  netrc.c getinfo.c transfer.c strequal.c easy.c security.c      	\
  curl_fnmatch.c fileinfo.c ftplistparser.c wildcard.c krb5.c		\
  memdebug.c http_chunks.c strtok.c connect.c llist.c hash.c multi.c	\
  content_encoding.c share.c http_digest.c md4.c md5.c	\
  http_negotiate.c inet_pton.c strtoofft.c strerror.c amigaos.c		\
  hostasyn.c hostip4.c hostip6.c hostsyn.c inet_ntop.c parsedate.c	\
  select.c gtls.c sslgen.c tftp.c splay.c strdup.c socks.c ssh.c nss.c	\
  qssl.c rawstr.c curl_addrinfo.c socks_gssapi.c socks_sspi.c		\
  curl_sspi.c slist.c nonblock.c curl_memrchr.c imap.c pop3.c smtp.c	\
  pingpong.c rtsp.c curl_threads.c warnless.c hmac.c polarssl.c		\
  polarssl_threadlock.c curl_rtmp.c openldap.c curl_gethostname.c	\
  gopher.c axtls.c idn_win32.c http_negotiate_sspi.c cyassl.c		\
  http_proxy.c non-ascii.c asyn-ares.c asyn-thread.c curl_gssapi.c	\
  curl_ntlm.c curl_ntlm_wb.c curl_ntlm_core.c curl_ntlm_msgs.c		\
  curl_sasl.c curl_schannel.c curl_multibyte.c curl_darwinssl.c		\
  hostcheck.c bundles.c conncache.c pipeline.c dotdot.c x509asn1.c      \
  gskit.c http2.c

HHEADERS = arpa_telnet.h netrc.h file.h timeval.h qssl.h hostip.h	\
  progress.h formdata.h cookie.h http.h sendf.h ftp.h url.h dict.h	\
  if2ip.h speedcheck.h urldata.h curl_ldap.h ssluse.h escape.h telnet.h	\
  getinfo.h strequal.h curl_sec.h memdebug.h http_chunks.h		\
  curl_fnmatch.h wildcard.h fileinfo.h ftplistparser.h strtok.h		\
  connect.h llist.h hash.h content_encoding.h share.h curl_md4.h	\
  curl_md5.h http_digest.h http_negotiate.h inet_pton.h amigaos.h	\
  strtoofft.h strerror.h inet_ntop.h curlx.h curl_memory.h curl_setup.h	\
  transfer.h select.h easyif.h multiif.h parsedate.h sslgen.h gtls.h	\
  tftp.h sockaddr.h splay.h strdup.h socks.h ssh.h nssg.h curl_base64.h	\
  rawstr.h curl_addrinfo.h curl_sspi.h slist.h nonblock.h		\
  curl_memrchr.h imap.h pop3.h smtp.h pingpong.h rtsp.h curl_threads.h	\
  warnless.h curl_hmac.h polarssl.h polarssl_threadlock.h curl_rtmp.h	\
  curl_gethostname.h gopher.h axtls.h cyassl.h http_proxy.h non-ascii.h	\
  asyn.h curl_ntlm.h curl_gssapi.h curl_ntlm_wb.h curl_ntlm_core.h	\
  curl_ntlm_msgs.h curl_sasl.h curl_schannel.h curl_multibyte.h		\
  curl_darwinssl.h hostcheck.h bundles.h conncache.h curl_setup_once.h	\
  multihandle.h setup-vms.h pipeline.h dotdot.h x509asn1.h gskit.h	\
  http2.h sigpipe.h
