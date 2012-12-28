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
  netrc.c getinfo.c transfer.c strequal.c easy.c security.c krb4.c	\
  curl_fnmatch.c fileinfo.c ftplistparser.c wildcard.c krb5.c		\
  memdebug.c http_chunks.c strtok.c connect.c llist.c hash.c multi.c	\
  content_encoding.c share.c http_digest.c md4.c md5.c curl_rand.c	\
  http_negotiate.c inet_pton.c strtoofft.c strerror.c amigaos.c		\
  hostasyn.c hostip4.c hostip6.c hostsyn.c inet_ntop.c parsedate.c	\
  select.c gtls.c sslgen.c tftp.c splay.c strdup.c socks.c ssh.c nss.c	\
  qssl.c rawstr.c curl_addrinfo.c socks_gssapi.c socks_sspi.c		\
  curl_sspi.c slist.c nonblock.c curl_memrchr.c imap.c pop3.c smtp.c	\
  pingpong.c rtsp.c curl_threads.c warnless.c hmac.c polarssl.c		\
  curl_rtmp.c openldap.c curl_gethostname.c gopher.c axtls.c		\
  idn_win32.c http_negotiate_sspi.c cyassl.c http_proxy.c non-ascii.c	\
  asyn-ares.c asyn-thread.c curl_gssapi.c curl_ntlm.c curl_ntlm_wb.c	\
  curl_ntlm_core.c curl_ntlm_msgs.c curl_sasl.c curl_schannel.c	        \
  curl_multibyte.c curl_darwinssl.c hostcheck.c                         \
  bundles.c conncache.c

HHEADERS = \
  curl_addrinfo.h \
  curl_amigaos.h \
  curl_arpa_telnet.h \
  curl_asyn.h \
  curl_axtls.h \
  curl_base64.h \
  curl_bundles.h \
  curl_conncache.h \
  curl_connect.h \
  curl_content_encoding.h \
  curl_cookie.h \
  curl_cyassl.h \
  curl_darwinssl.h \
  curl_dict.h \
  curl_easyif.h \
  curl_escape.h \
  curl_file.h \
  curl_fileinfo.h \
  curl_fnmatch.h \
  curl_formdata.h \
  curl_ftp.h \
  curl_ftplistparser.h \
  curl_gethostname.h \
  curl_getinfo.h \
  curl_gopher.h \
  curl_gssapi.h \
  curl_gtls.h \
  curl_hash.h \
  curl_hmac.h \
  curl_hostcheck.h \
  curl_hostip.h \
  curl_http.h \
  curl_http_chunks.h \
  curl_http_digest.h \
  curl_http_negotiate.h \
  curl_http_proxy.h \
  curl_if2ip.h \
  curl_imap.h \
  curl_inet_ntop.h \
  curl_inet_pton.h \
  curl_krb4.h \
  curl_ldap.h \
  curl_llist.h \
  curl_md4.h \
  curl_md5.h \
  curl_memdebug.h \
  curl_memory.h \
  curl_memrchr.h \
  curl_multibyte.h \
  curl_multiif.h \
  curl_netrc.h \
  curl_non-ascii.h \
  curl_nonblock.h \
  curl_nssg.h \
  curl_ntlm.h \
  curl_ntlm_core.h \
  curl_ntlm_msgs.h \
  curl_ntlm_wb.h \
  curl_parsedate.h \
  curl_pingpong.h \
  curl_polarssl.h \
  curl_pop3.h \
  curl_progress.h \
  curl_qssl.h \
  curl_rand.h \
  curl_rawstr.h \
  curl_rtmp.h \
  curl_rtsp.h \
  curl_sasl.h \
  curl_schannel.h \
  curl_select.h \
  curl_sendf.h \
  curl_setup.h \
  curl_setup_once.h \
  curl_share.h \
  curl_slist.h \
  curl_smtp.h \
  curl_sockaddr.h \
  curl_socks.h \
  curl_speedcheck.h \
  curl_splay.h \
  curl_ssh.h \
  curl_sslgen.h \
  curl_ssluse.h \
  curl_sspi.h \
  curl_strdup.h \
  curl_strequal.h \
  curl_strerror.h \
  curl_strtok.h \
  curl_strtoofft.h \
  curl_telnet.h \
  curl_tftp.h \
  curl_threads.h \
  curl_timeval.h \
  curl_transfer.h \
  curl_url.h \
  curl_urldata.h \
  curl_wildcard.h \
  curlx.h

