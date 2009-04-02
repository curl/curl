SET(LIB_NAME libcurl)

CONFIGURE_FILE(${CURL_SOURCE_DIR}/include/curl/curlbuild.h.cmake
  ${CURL_BINARY_DIR}/include/curl/curlbuild.h)
CONFIGURE_FILE(config.h.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/config.h)

SET(libCurl_HEADERS
	${CMAKE_CURRENT_BINARY_DIR}/config.h
	${CURL_BINARY_DIR}/include/curl/curlbuild.h
	arpa_telnet.h netrc.h file.h timeval.h qssl.h hostip.h
	progress.h formdata.h cookie.h http.h sendf.h ftp.h url.h dict.h
	if2ip.h speedcheck.h urldata.h curl_ldap.h ssluse.h escape.h telnet.h
	getinfo.h strequal.h krb4.h memdebug.h http_chunks.h
	strtok.h connect.h llist.h hash.h content_encoding.h share.h
	curl_md5.h http_digest.h http_negotiate.h http_ntlm.h inet_pton.h
	strtoofft.h strerror.h inet_ntop.h curlx.h memory.h setup.h
	transfer.h select.h easyif.h multiif.h parsedate.h sslgen.h gtls.h
	tftp.h sockaddr.h splay.h strdup.h setup_once.h socks.h ssh.h nssg.h
	curl_base64.h rawstr.h curl_addrinfo.h curl_sspi.h slist.h
)

SET(libCurl_SRCS
  #  amigaos.c - does not build on AmigaOS
  base64.c
  connect.c
  content_encoding.c
  cookie.c
  curl_addrinfo.c
  curl_sspi.c
  dict.c
  easy.c
  escape.c
  file.c
  formdata.c
  ftp.c
  getenv.c
  getinfo.c
  gtls.c
  hash.c
  hostares.c
  hostasyn.c
  hostip4.c
  hostip6.c
  hostip.c
  hostsyn.c
  hostthre.c
  http.c
  http_chunks.c
  http_digest.c
  http_negotiate.c
  http_ntlm.c
  if2ip.c
  inet_ntop.c
  inet_pton.c
  krb4.c
  ldap.c
  llist.c
  md5.c
#  memdebug.c -not used
  mprintf.c
  multi.c
  netrc.c
  # nwlib.c - Not used
  parsedate.c
  progress.c
  rawstr.c
  security.c
  select.c
  sendf.c
  slist.c
  share.c
  socks.c
  speedcheck.c
  splay.c
  ssh.c
  sslgen.c
  ssluse.c
  strdup.c
  strequal.c
  strerror.c
  # strtok.c - specify later
  # strtoofft.c - specify later
  telnet.c
  tftp.c
  timeval.c
  transfer.c
  url.c
  version.c
)

IF(MSVC)
	LIST(APPEND libCurl_SRCS libcurl.rc)
ENDIF()

# if we have Kerberos 4, right now this is never on
#OPTION(CURL_KRB4 "Use Kerberos 4" OFF)
IF(CURL_KRB4)
  SET(libCurl_SRCS ${libCurl_SRCS}
    krb4.c
    security.c
    )
ENDIF(CURL_KRB4)

#OPTION(CURL_MALLOC_DEBUG "Debug mallocs in Curl" OFF)
MARK_AS_ADVANCED(CURL_MALLOC_DEBUG)
IF(CURL_MALLOC_DEBUG)
  SET(libCurl_SRCS ${libCurl_SRCS}
    memdebug.c
    )
ENDIF(CURL_MALLOC_DEBUG)

IF(CMAKE_USE_OPENSSL AND OPENSSL_FOUND)
	INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
ENDIF()

IF(CURL_ZLIB AND ZLIB_FOUND)
	INCLUDE_DIRECTORIES(${ZLIB_INCLUDE_DIR})
ENDIF()

IF(HAVE_FEATURES_H)
  SET_SOURCE_FILES_PROPERTIES(
    cookie.c
    easy.c
    formdata.c
    getenv.c
    hash.c
    http.c
    if2ip.c 
    mprintf.c
    multi.c
    sendf.c
    telnet.c
    transfer.c
    url.c
    COMPILE_FLAGS -D_BSD_SOURCE)
ENDIF(HAVE_FEATURES_H)

#strtoll \
#socket \
#select \
#strdup \
#strstr \
#strtok_r \
#uname \
#strcasecmp \
#stricmp \
#strcmpi \
#gethostbyaddr \
#gettimeofday \
#inet_addr \
#inet_ntoa \
#inet_pton \
#perror \
#closesocket \
#siginterrupt \
#sigaction \
#signal \
#getpass_r \
#strlcat \
#getpwuid \
#geteuid \
#dlopen \
#utime \
#sigsetjmp \
#basename \
#setlocale \
#ftruncate \
#pipe \
#poll \
#getprotobyname \
#getrlimit \
#setrlimit \
#fork

# only build compat strtok if we need to
IF (NOT HAVE_STRTOK_R)
  SET(libCurl_SRCS ${libCurl_SRCS}
    strtok.c
    )
ENDIF (NOT HAVE_STRTOK_R)

# only build compat strtoofft if we need to
IF(NOT HAVE_STRTOLL AND NOT HAVE__STRTOI64)
  SET(libCurl_SRCS ${libCurl_SRCS}
    strtoofft.c
    )
ENDIF(NOT HAVE_STRTOLL AND NOT HAVE__STRTOI64)

# The rest of the build

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/../include)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/..)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../include)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/..)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})

IF(CURL_STATICLIB)
	SET(CURL_USER_DEFINED_DYNAMIC_OR_STATIC STATIC)
ELSE()
	SET(CURL_USER_DEFINED_DYNAMIC_OR_STATIC SHARED)
ENDIF()

ADD_LIBRARY(
	${LIB_NAME}
	${CURL_USER_DEFINED_DYNAMIC_OR_STATIC}
	${libCurl_HEADERS} ${libCurl_SRCS}
)

TARGET_LINK_LIBRARIES(${LIB_NAME} ${CURL_LIBS})

IF(WIN32)
	ADD_DEFINITIONS( -D_USRDLL )
ENDIF()

IF(CURL_ZLIB AND ZLIB_FOUND)
	TARGET_LINK_LIBRARIES(${LIB_NAME} ${ZLIB_LIBRARIES})
	#ADD_DEFINITIONS( -DHAVE_ZLIB_H -DHAVE_ZLIB -DHAVE_LIBZ )
ENDIF()

# IF(CURL_SSL AND CURL_CONFIG_HAS_BEEN_RUN_BEFORE)
	# LIST(APPEND DEPENDENCIES_NAMES OpenSSL)
	# ADD_DEFINITIONS( -DUSE_SSLEAY )
# ENDIF()

# IF(MSVC)
	# IF(NOT BUILD_RELEASE_DEBUG_DIRS)
		# # Ugly workaround to remove the "/debug" or "/release" in each output
		# SET_TARGET_PROPERTIES(${LIB_NAME} PROPERTIES PREFIX "../")
		# SET_TARGET_PROPERTIES(${LIB_NAME} PROPERTIES IMPORT_PREFIX "../")
	# ENDIF()
	# # Add "_imp" as a suffix before the extension
	# SET_TARGET_PROPERTIES(${LIB_NAME} PROPERTIES IMPORT_SUFFIX "_imp.lib")
# ENDIF()
