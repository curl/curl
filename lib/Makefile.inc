# ./lib/Makefile.inc

CSOURCES = file.c timeval.c base64.c hostip.c progress.c formdata.c	\
  cookie.c http.c sendf.c ftp.c url.c dict.c if2ip.c speedcheck.c	\
  ldap.c ssluse.c version.c getenv.c escape.c mprintf.c telnet.c	\
  netrc.c getinfo.c transfer.c strequal.c easy.c security.c krb4.c	\
  krb5.c memdebug.c http_chunks.c strtok.c connect.c llist.c hash.c	\
  multi.c content_encoding.c share.c http_digest.c md5.c		\
  http_negotiate.c http_ntlm.c inet_pton.c strtoofft.c strerror.c	\
  hostares.c hostasyn.c hostip4.c hostip6.c hostsyn.c hostthre.c	\
  inet_ntop.c parsedate.c select.c gtls.c sslgen.c tftp.c splay.c	\
  strdup.c socks.c ssh.c nss.c qssl.c rawstr.c curl_addrinfo.c          \
  socks_gssapi.c socks_sspi.c curl_sspi.c

HHEADERS = arpa_telnet.h netrc.h file.h timeval.h qssl.h hostip.h	\
  progress.h formdata.h cookie.h http.h sendf.h ftp.h url.h dict.h	\
  if2ip.h speedcheck.h urldata.h curl_ldap.h ssluse.h escape.h telnet.h	\
  getinfo.h strequal.h krb4.h memdebug.h http_chunks.h	                \
  strtok.h connect.h llist.h hash.h content_encoding.h share.h		\
  curl_md5.h http_digest.h http_negotiate.h http_ntlm.h inet_pton.h	\
  strtoofft.h strerror.h inet_ntop.h curlx.h memory.h setup.h		\
  transfer.h select.h easyif.h multiif.h parsedate.h sslgen.h gtls.h	\
  tftp.h sockaddr.h splay.h strdup.h setup_once.h socks.h ssh.h nssg.h	\
  curl_base64.h rawstr.h curl_addrinfo.h curl_sspi.h
