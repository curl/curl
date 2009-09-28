#######################################################################
#                                                                     #
#  MAKEFILE NAME.....  curl.mak                                       #
#                                                                     #
#  DESCRIPTION.....    This is the makefile for libcurl.              #
#                                                                     #
#######################################################################

APP := CURL

TPF_RUN_TPFSOCHK := NO

#######################################################################
# Define any additional libs needed to link
#######################################################################

LIBS := CRYP CSSL

#######################################################################
# Define the envs needed to build this module
#######################################################################

maketpf_env := curllib
maketpf_env += openssl
maketpf_env += base_rt
maketpf_env += system

#######################################################################
# Segments to be compiled with gcc compiler
#######################################################################
#
### lib directory:
C_SRC := base64.c
C_SRC += connect.c
C_SRC += content_encoding.c
C_SRC += cookie.c
C_SRC += curl_addrinfo.c
C_SRC += curl_memrchr.c
C_SRC += curl_rand.c
C_SRC += curl_sspi.c
C_SRC += dict.c
C_SRC += easy.c
C_SRC += escape.c
C_SRC += file.c
C_SRC += formdata.c
C_SRC += ftp.c
C_SRC += getenv.c
C_SRC += getinfo.c
C_SRC += gtls.c
C_SRC += hash.c
C_SRC += hostares.c
C_SRC += hostasyn.c
C_SRC += hostip.c
C_SRC += hostip4.c
C_SRC += hostip6.c
C_SRC += hostsyn.c
C_SRC += hostthre.c
C_SRC += http.c
C_SRC += http_chunks.c
C_SRC += http_digest.c
C_SRC += http_negotiate.c
C_SRC += http_ntlm.c
C_SRC += if2ip.c
C_SRC += inet_ntop.c
C_SRC += inet_pton.c
C_SRC += krb4.c
C_SRC += krb5.c
C_SRC += ldap.c
C_SRC += llist.c
C_SRC += md5.c
C_SRC += memdebug.c
C_SRC += mprintf.c
C_SRC += multi.c
C_SRC += netrc.c
C_SRC += nonblock.c
C_SRC += nss.c
C_SRC += parsedate.c
C_SRC += progress.c
C_SRC += qssl.c
C_SRC += rawstr.c
C_SRC += security.c
C_SRC += select.c
C_SRC += sendf.c
C_SRC += share.c
C_SRC += slist.c
C_SRC += socks.c
C_SRC += socks_gssapi.c
C_SRC += socks_sspi.c
C_SRC += speedcheck.c
C_SRC += splay.c
C_SRC += ssh.c
C_SRC += ssluse.c
C_SRC += sslgen.c
C_SRC += strdup.c
C_SRC += strequal.c
C_SRC += strerror.c
C_SRC += strtok.c
C_SRC += strtoofft.c
C_SRC += telnet.c
C_SRC += tftp.c
C_SRC += timeval.c
C_SRC += transfer.c
C_SRC += url.c
C_SRC += version.c

#######################################################################
# Additions and overrides for gcc compiler flags
#######################################################################

# suppress expected warnings in the ported code:
CFLAGS_CURL += -w

# use SSL
# (overrides Curl's lib/config-tpf.h file)
CFLAGS_CURL += -DUSE_OPENSSL
CFLAGS_CURL += -DUSE_SSLEAY

# disable all protocols except FTP and HTTP
# (overrides Curl's lib/config-tpf.h file)
CFLAGS_CURL += -DCURL_DISABLE_DICT
CFLAGS_CURL += -DCURL_DISABLE_FILE
CFLAGS_CURL += -DCURL_DISABLE_LDAP
CFLAGS_CURL += -DCURL_DISABLE_TELNET
CFLAGS_CURL += -DCURL_DISABLE_TFTP

#######################################################################
# Include the maketpf.rules
#######################################################################

include maketpf.rules

