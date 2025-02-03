#ifndef FETCHINC_FETCH_H
#define FETCHINC_FETCH_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

/*
 * If you have libfetch problems, all docs and details are found here:
 *   https://fetch.se/libfetch/
 */

#ifdef FETCH_NO_OLDIES
#define FETCH_STRICTER /* not used since 8.11.0 */
#endif

/* Compile-time deprecation macros. */
#if (defined(__GNUC__) &&                                              \
  ((__GNUC__ > 12) || ((__GNUC__ == 12) && (__GNUC_MINOR__ >= 1))) ||  \
  (defined(__clang__) && __clang_major__ >= 3) ||                      \
  defined(__IAR_SYSTEMS_ICC__)) &&                                     \
  !defined(__INTEL_COMPILER) &&                                        \
  !defined(FETCH_DISABLE_DEPRECATION) && !defined(BUILDING_LIBFETCH)
#define FETCH_DEPRECATED(version, message)                       \
  __attribute__((deprecated("since " # version ". " message)))
#if defined(__IAR_SYSTEMS_ICC__)
#define FETCH_IGNORE_DEPRECATION(statements) \
      _Pragma("diag_suppress=Pe1444") \
      statements \
      _Pragma("diag_default=Pe1444")
#else
#define FETCH_IGNORE_DEPRECATION(statements) \
      _Pragma("GCC diagnostic push") \
      _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"") \
      statements \
      _Pragma("GCC diagnostic pop")
#endif
#else
#define FETCH_DEPRECATED(version, message)
#define FETCH_IGNORE_DEPRECATION(statements)     statements
#endif

#include "fetchver.h"         /* libfetch version defines   */
#include "system.h"          /* determine things runtime */

#include <stdio.h>
#include <limits.h>

#if defined(__FreeBSD__) || defined(__MidnightBSD__)
/* Needed for __FreeBSD_version or __MidnightBSD_version symbol definition */
#include <sys/param.h>
#endif

/* The include stuff here below is mainly for time_t! */
#include <sys/types.h>
#include <time.h>

#if defined(_WIN32) && !defined(_WIN32_WCE) && !defined(__CYGWIN__)
#if !(defined(_WINSOCKAPI_) || defined(_WINSOCK_H) || \
      defined(__LWIP_OPT_H__) || defined(LWIP_HDR_OPT_H))
/* The check above prevents the winsock2.h inclusion if winsock.h already was
   included, since they cannot co-exist without problems */
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#endif

/* HP-UX systems version 9, 10 and 11 lack sys/select.h and so does oldish
   libc5-based Linux systems. Only include it on systems that are known to
   require it! */
#if defined(_AIX) || defined(__NOVELL_LIBC__) || defined(__NetBSD__) || \
    defined(__minix) || defined(__INTEGRITY) || \
    defined(ANDROID) || defined(__ANDROID__) || defined(__OpenBSD__) || \
    defined(__CYGWIN__) || defined(AMIGA) || defined(__NuttX__) || \
   (defined(__FreeBSD_version) && (__FreeBSD_version < 800000)) || \
   (defined(__MidnightBSD_version) && (__MidnightBSD_version < 100000)) || \
    defined(__sun__) || defined(__serenity__) || defined(__vxworks__)
#include <sys/select.h>
#endif

#if !defined(_WIN32) && !defined(_WIN32_WCE)
#include <sys/socket.h>
#endif

#if !defined(_WIN32)
#include <sys/time.h>
#endif

/* Compatibility for non-Clang compilers */
#ifndef __has_declspec_attribute
#  define __has_declspec_attribute(x) 0
#endif

#ifdef  __cplusplus
extern "C" {
#endif

typedef void FETCH;
typedef void FETCHSH;

/*
 * libfetch external API function linkage decorations.
 */

#ifdef FETCH_STATICLIB
#  define FETCH_EXTERN
#elif defined(_WIN32) || \
     (__has_declspec_attribute(dllexport) && \
      __has_declspec_attribute(dllimport))
#  if defined(BUILDING_LIBFETCH)
#    define FETCH_EXTERN  __declspec(dllexport)
#  else
#    define FETCH_EXTERN  __declspec(dllimport)
#  endif
#elif defined(BUILDING_LIBFETCH) && defined(FETCH_HIDDEN_SYMBOLS)
#  define FETCH_EXTERN FETCH_EXTERN_SYMBOL
#else
#  define FETCH_EXTERN
#endif

#ifndef fetch_socket_typedef
/* socket typedef */
#if defined(_WIN32) && !defined(__LWIP_OPT_H__) && !defined(LWIP_HDR_OPT_H)
typedef SOCKET fetch_socket_t;
#define FETCH_SOCKET_BAD INVALID_SOCKET
#else
typedef int fetch_socket_t;
#define FETCH_SOCKET_BAD -1
#endif
#define fetch_socket_typedef
#endif /* fetch_socket_typedef */

/* enum for the different supported SSL backends */
typedef enum {
  FETCHSSLBACKEND_NONE = 0,
  FETCHSSLBACKEND_OPENSSL = 1,
  FETCHSSLBACKEND_GNUTLS = 2,
  FETCHSSLBACKEND_NSS                    FETCH_DEPRECATED(8.3.0, "") = 3,
  FETCHSSLBACKEND_OBSOLETE4 = 4,  /* Was QSOSSL. */
  FETCHSSLBACKEND_GSKIT                  FETCH_DEPRECATED(8.3.0, "") = 5,
  FETCHSSLBACKEND_POLARSSL               FETCH_DEPRECATED(7.69.0, "") = 6,
  FETCHSSLBACKEND_WOLFSSL = 7,
  FETCHSSLBACKEND_SCHANNEL = 8,
  FETCHSSLBACKEND_SECURETRANSPORT = 9,
  FETCHSSLBACKEND_AXTLS                  FETCH_DEPRECATED(7.61.0, "") = 10,
  FETCHSSLBACKEND_MBEDTLS = 11,
  FETCHSSLBACKEND_MESALINK               FETCH_DEPRECATED(7.82.0, "") = 12,
  FETCHSSLBACKEND_BEARSSL = 13,
  FETCHSSLBACKEND_RUSTLS = 14
} fetch_sslbackend;

/* aliases for library clones and renames */
#define FETCHSSLBACKEND_AWSLC FETCHSSLBACKEND_OPENSSL
#define FETCHSSLBACKEND_BORINGSSL FETCHSSLBACKEND_OPENSSL
#define FETCHSSLBACKEND_LIBRESSL FETCHSSLBACKEND_OPENSSL

/* deprecated names: */
#define FETCHSSLBACKEND_CYASSL FETCHSSLBACKEND_WOLFSSL
#define FETCHSSLBACKEND_DARWINSSL FETCHSSLBACKEND_SECURETRANSPORT

struct fetch_httppost {
  struct fetch_httppost *next;       /* next entry in the list */
  char *name;                       /* pointer to allocated name */
  long namelength;                  /* length of name length */
  char *contents;                   /* pointer to allocated data contents */
  long contentslength;              /* length of contents field, see also
                                       FETCH_HTTPPOST_LARGE */
  char *buffer;                     /* pointer to allocated buffer contents */
  long bufferlength;                /* length of buffer field */
  char *contenttype;                /* Content-Type */
  struct fetch_slist *contentheader; /* list of extra headers for this form */
  struct fetch_httppost *more;       /* if one field name has more than one
                                       file, this link should link to following
                                       files */
  long flags;                       /* as defined below */

/* specified content is a filename */
#define FETCH_HTTPPOST_FILENAME (1<<0)
/* specified content is a filename */
#define FETCH_HTTPPOST_READFILE (1<<1)
/* name is only stored pointer do not free in formfree */
#define FETCH_HTTPPOST_PTRNAME (1<<2)
/* contents is only stored pointer do not free in formfree */
#define FETCH_HTTPPOST_PTRCONTENTS (1<<3)
/* upload file from buffer */
#define FETCH_HTTPPOST_BUFFER (1<<4)
/* upload file from pointer contents */
#define FETCH_HTTPPOST_PTRBUFFER (1<<5)
/* upload file contents by using the regular read callback to get the data and
   pass the given pointer as custom pointer */
#define FETCH_HTTPPOST_CALLBACK (1<<6)
/* use size in 'contentlen', added in 7.46.0 */
#define FETCH_HTTPPOST_LARGE (1<<7)

  char *showfilename;               /* The filename to show. If not set, the
                                       actual filename will be used (if this
                                       is a file part) */
  void *userp;                      /* custom pointer used for
                                       HTTPPOST_CALLBACK posts */
  fetch_off_t contentlen;            /* alternative length of contents
                                       field. Used if FETCH_HTTPPOST_LARGE is
                                       set. Added in 7.46.0 */
};


/* This is a return code for the progress callback that, when returned, will
   signal libfetch to continue executing the default progress function */
#define FETCH_PROGRESSFUNC_CONTINUE 0x10000001

/* This is the FETCHOPT_PROGRESSFUNCTION callback prototype. It is now
   considered deprecated but was the only choice up until 7.31.0 */
typedef int (*fetch_progress_callback)(void *clientp,
                                      double dltotal,
                                      double dlnow,
                                      double ultotal,
                                      double ulnow);

/* This is the FETCHOPT_XFERINFOFUNCTION callback prototype. It was introduced
   in 7.32.0, avoids the use of floating point numbers and provides more
   detailed information. */
typedef int (*fetch_xferinfo_callback)(void *clientp,
                                      fetch_off_t dltotal,
                                      fetch_off_t dlnow,
                                      fetch_off_t ultotal,
                                      fetch_off_t ulnow);

#ifndef FETCH_MAX_READ_SIZE
  /* The maximum receive buffer size configurable via FETCHOPT_BUFFERSIZE. */
#define FETCH_MAX_READ_SIZE (10*1024*1024)
#endif

#ifndef FETCH_MAX_WRITE_SIZE
  /* Tests have proven that 20K is a bad buffer size for uploads on Windows,
     while 16K for some odd reason performed a lot better. We do the ifndef
     check to allow this value to easier be changed at build time for those
     who feel adventurous. The practical minimum is about 400 bytes since
     libfetch uses a buffer of this size as a scratch area (unrelated to
     network send operations). */
#define FETCH_MAX_WRITE_SIZE 16384
#endif

#ifndef FETCH_MAX_HTTP_HEADER
/* The only reason to have a max limit for this is to avoid the risk of a bad
   server feeding libfetch with a never-ending header that will cause reallocs
   infinitely */
#define FETCH_MAX_HTTP_HEADER (100*1024)
#endif

/* This is a magic return code for the write callback that, when returned,
   will signal libfetch to pause receiving on the current transfer. */
#define FETCH_WRITEFUNC_PAUSE 0x10000001

/* This is a magic return code for the write callback that, when returned,
   will signal an error from the callback. */
#define FETCH_WRITEFUNC_ERROR 0xFFFFFFFF

typedef size_t (*fetch_write_callback)(char *buffer,
                                      size_t size,
                                      size_t nitems,
                                      void *outstream);

/* This callback will be called when a new resolver request is made */
typedef int (*fetch_resolver_start_callback)(void *resolver_state,
                                            void *reserved, void *userdata);

/* enumeration of file types */
typedef enum {
  FETCHFILETYPE_FILE = 0,
  FETCHFILETYPE_DIRECTORY,
  FETCHFILETYPE_SYMLINK,
  FETCHFILETYPE_DEVICE_BLOCK,
  FETCHFILETYPE_DEVICE_CHAR,
  FETCHFILETYPE_NAMEDPIPE,
  FETCHFILETYPE_SOCKET,
  FETCHFILETYPE_DOOR, /* is possible only on Sun Solaris now */

  FETCHFILETYPE_UNKNOWN /* should never occur */
} fetchfiletype;

#define FETCHFINFOFLAG_KNOWN_FILENAME    (1<<0)
#define FETCHFINFOFLAG_KNOWN_FILETYPE    (1<<1)
#define FETCHFINFOFLAG_KNOWN_TIME        (1<<2)
#define FETCHFINFOFLAG_KNOWN_PERM        (1<<3)
#define FETCHFINFOFLAG_KNOWN_UID         (1<<4)
#define FETCHFINFOFLAG_KNOWN_GID         (1<<5)
#define FETCHFINFOFLAG_KNOWN_SIZE        (1<<6)
#define FETCHFINFOFLAG_KNOWN_HLINKCOUNT  (1<<7)

/* Information about a single file, used when doing FTP wildcard matching */
struct fetch_fileinfo {
  char *filename;
  fetchfiletype filetype;
  time_t time; /* always zero! */
  unsigned int perm;
  int uid;
  int gid;
  fetch_off_t size;
  long int hardlinks;

  struct {
    /* If some of these fields is not NULL, it is a pointer to b_data. */
    char *time;
    char *perm;
    char *user;
    char *group;
    char *target; /* pointer to the target filename of a symlink */
  } strings;

  unsigned int flags;

  /* These are libfetch private struct fields. Previously used by libfetch, so
     they must never be interfered with. */
  char *b_data;
  size_t b_size;
  size_t b_used;
};

/* return codes for FETCHOPT_CHUNK_BGN_FUNCTION */
#define FETCH_CHUNK_BGN_FUNC_OK      0
#define FETCH_CHUNK_BGN_FUNC_FAIL    1 /* tell the lib to end the task */
#define FETCH_CHUNK_BGN_FUNC_SKIP    2 /* skip this chunk over */

/* if splitting of data transfer is enabled, this callback is called before
   download of an individual chunk started. Note that parameter "remains" works
   only for FTP wildcard downloading (for now), otherwise is not used */
typedef long (*fetch_chunk_bgn_callback)(const void *transfer_info,
                                        void *ptr,
                                        int remains);

/* return codes for FETCHOPT_CHUNK_END_FUNCTION */
#define FETCH_CHUNK_END_FUNC_OK      0
#define FETCH_CHUNK_END_FUNC_FAIL    1 /* tell the lib to end the task */

/* If splitting of data transfer is enabled this callback is called after
   download of an individual chunk finished.
   Note! After this callback was set then it have to be called FOR ALL chunks.
   Even if downloading of this chunk was skipped in CHUNK_BGN_FUNC.
   This is the reason why we do not need "transfer_info" parameter in this
   callback and we are not interested in "remains" parameter too. */
typedef long (*fetch_chunk_end_callback)(void *ptr);

/* return codes for FNMATCHFUNCTION */
#define FETCH_FNMATCHFUNC_MATCH    0 /* string corresponds to the pattern */
#define FETCH_FNMATCHFUNC_NOMATCH  1 /* pattern does not match the string */
#define FETCH_FNMATCHFUNC_FAIL     2 /* an error occurred */

/* callback type for wildcard downloading pattern matching. If the
   string matches the pattern, return FETCH_FNMATCHFUNC_MATCH value, etc. */
typedef int (*fetch_fnmatch_callback)(void *ptr,
                                     const char *pattern,
                                     const char *string);

/* These are the return codes for the seek callbacks */
#define FETCH_SEEKFUNC_OK       0
#define FETCH_SEEKFUNC_FAIL     1 /* fail the entire transfer */
#define FETCH_SEEKFUNC_CANTSEEK 2 /* tell libfetch seeking cannot be done, so
                                    libfetch might try other means instead */
typedef int (*fetch_seek_callback)(void *instream,
                                  fetch_off_t offset,
                                  int origin); /* 'whence' */

/* This is a return code for the read callback that, when returned, will
   signal libfetch to immediately abort the current transfer. */
#define FETCH_READFUNC_ABORT 0x10000000
/* This is a return code for the read callback that, when returned, will
   signal libfetch to pause sending data on the current transfer. */
#define FETCH_READFUNC_PAUSE 0x10000001

/* Return code for when the trailing headers' callback has terminated
   without any errors */
#define FETCH_TRAILERFUNC_OK 0
/* Return code for when was an error in the trailing header's list and we
  want to abort the request */
#define FETCH_TRAILERFUNC_ABORT 1

typedef size_t (*fetch_read_callback)(char *buffer,
                                      size_t size,
                                      size_t nitems,
                                      void *instream);

typedef int (*fetch_trailer_callback)(struct fetch_slist **list,
                                      void *userdata);

typedef enum {
  FETCHSOCKTYPE_IPCXN,  /* socket created for a specific IP connection */
  FETCHSOCKTYPE_ACCEPT, /* socket created by accept() call */
  FETCHSOCKTYPE_LAST    /* never use */
} fetchsocktype;

/* The return code from the sockopt_callback can signal information back
   to libfetch: */
#define FETCH_SOCKOPT_OK 0
#define FETCH_SOCKOPT_ERROR 1 /* causes libfetch to abort and return
                                FETCHE_ABORTED_BY_CALLBACK */
#define FETCH_SOCKOPT_ALREADY_CONNECTED 2

typedef int (*fetch_sockopt_callback)(void *clientp,
                                     fetch_socket_t fetchfd,
                                     fetchsocktype purpose);

struct fetch_sockaddr {
  int family;
  int socktype;
  int protocol;
  unsigned int addrlen; /* addrlen was a socklen_t type before 7.18.0 but it
                           turned really ugly and painful on the systems that
                           lack this type */
  struct sockaddr addr;
};

typedef fetch_socket_t
(*fetch_opensocket_callback)(void *clientp,
                            fetchsocktype purpose,
                            struct fetch_sockaddr *address);

typedef int
(*fetch_closesocket_callback)(void *clientp, fetch_socket_t item);

typedef enum {
  FETCHIOE_OK,            /* I/O operation successful */
  FETCHIOE_UNKNOWNCMD,    /* command was unknown to callback */
  FETCHIOE_FAILRESTART,   /* failed to restart the read */
  FETCHIOE_LAST           /* never use */
} fetchioerr;

typedef enum {
  FETCHIOCMD_NOP,         /* no operation */
  FETCHIOCMD_RESTARTREAD, /* restart the read stream from start */
  FETCHIOCMD_LAST         /* never use */
} fetchiocmd;

typedef fetchioerr (*fetch_ioctl_callback)(FETCH *handle,
                                         int cmd,
                                         void *clientp);

#ifndef FETCH_DID_MEMORY_FUNC_TYPEDEFS
/*
 * The following typedef's are signatures of malloc, free, realloc, strdup and
 * calloc respectively. Function pointers of these types can be passed to the
 * fetch_global_init_mem() function to set user defined memory management
 * callback routines.
 */
typedef void *(*fetch_malloc_callback)(size_t size);
typedef void (*fetch_free_callback)(void *ptr);
typedef void *(*fetch_realloc_callback)(void *ptr, size_t size);
typedef char *(*fetch_strdup_callback)(const char *str);
typedef void *(*fetch_calloc_callback)(size_t nmemb, size_t size);

#define FETCH_DID_MEMORY_FUNC_TYPEDEFS
#endif

/* the kind of data that is passed to information_callback */
typedef enum {
  FETCHINFO_TEXT = 0,
  FETCHINFO_HEADER_IN,    /* 1 */
  FETCHINFO_HEADER_OUT,   /* 2 */
  FETCHINFO_DATA_IN,      /* 3 */
  FETCHINFO_DATA_OUT,     /* 4 */
  FETCHINFO_SSL_DATA_IN,  /* 5 */
  FETCHINFO_SSL_DATA_OUT, /* 6 */
  FETCHINFO_END
} fetch_infotype;

typedef int (*fetch_debug_callback)
       (FETCH *handle,      /* the handle/transfer this concerns */
        fetch_infotype type, /* what kind of data */
        char *data,        /* points to the data */
        size_t size,       /* size of the data pointed to */
        void *userptr);    /* whatever the user please */

/* This is the FETCHOPT_PREREQFUNCTION callback prototype. */
typedef int (*fetch_prereq_callback)(void *clientp,
                                    char *conn_primary_ip,
                                    char *conn_local_ip,
                                    int conn_primary_port,
                                    int conn_local_port);

/* Return code for when the pre-request callback has terminated without
   any errors */
#define FETCH_PREREQFUNC_OK 0
/* Return code for when the pre-request callback wants to abort the
   request */
#define FETCH_PREREQFUNC_ABORT 1

/* All possible error codes from all sorts of fetch functions. Future versions
   may return other values, stay prepared.

   Always add new return codes last. Never *EVER* remove any. The return
   codes must remain the same!
 */

typedef enum {
  FETCHE_OK = 0,
  FETCHE_UNSUPPORTED_PROTOCOL,    /* 1 */
  FETCHE_FAILED_INIT,             /* 2 */
  FETCHE_URL_MALFORMAT,           /* 3 */
  FETCHE_NOT_BUILT_IN,            /* 4 - [was obsoleted in August 2007 for
                                    7.17.0, reused in April 2011 for 7.21.5] */
  FETCHE_COULDNT_RESOLVE_PROXY,   /* 5 */
  FETCHE_COULDNT_RESOLVE_HOST,    /* 6 */
  FETCHE_COULDNT_CONNECT,         /* 7 */
  FETCHE_WEIRD_SERVER_REPLY,      /* 8 */
  FETCHE_REMOTE_ACCESS_DENIED,    /* 9 a service was denied by the server
                                    due to lack of access - when login fails
                                    this is not returned. */
  FETCHE_FTP_ACCEPT_FAILED,       /* 10 - [was obsoleted in April 2006 for
                                    7.15.4, reused in Dec 2011 for 7.24.0]*/
  FETCHE_FTP_WEIRD_PASS_REPLY,    /* 11 */
  FETCHE_FTP_ACCEPT_TIMEOUT,      /* 12 - timeout occurred accepting server
                                    [was obsoleted in August 2007 for 7.17.0,
                                    reused in Dec 2011 for 7.24.0]*/
  FETCHE_FTP_WEIRD_PASV_REPLY,    /* 13 */
  FETCHE_FTP_WEIRD_227_FORMAT,    /* 14 */
  FETCHE_FTP_CANT_GET_HOST,       /* 15 */
  FETCHE_HTTP2,                   /* 16 - A problem in the http2 framing layer.
                                    [was obsoleted in August 2007 for 7.17.0,
                                    reused in July 2014 for 7.38.0] */
  FETCHE_FTP_COULDNT_SET_TYPE,    /* 17 */
  FETCHE_PARTIAL_FILE,            /* 18 */
  FETCHE_FTP_COULDNT_RETR_FILE,   /* 19 */
  FETCHE_OBSOLETE20,              /* 20 - NOT USED */
  FETCHE_QUOTE_ERROR,             /* 21 - quote command failure */
  FETCHE_HTTP_RETURNED_ERROR,     /* 22 */
  FETCHE_WRITE_ERROR,             /* 23 */
  FETCHE_OBSOLETE24,              /* 24 - NOT USED */
  FETCHE_UPLOAD_FAILED,           /* 25 - failed upload "command" */
  FETCHE_READ_ERROR,              /* 26 - could not open/read from file */
  FETCHE_OUT_OF_MEMORY,           /* 27 */
  FETCHE_OPERATION_TIMEDOUT,      /* 28 - the timeout time was reached */
  FETCHE_OBSOLETE29,              /* 29 - NOT USED */
  FETCHE_FTP_PORT_FAILED,         /* 30 - FTP PORT operation failed */
  FETCHE_FTP_COULDNT_USE_REST,    /* 31 - the REST command failed */
  FETCHE_OBSOLETE32,              /* 32 - NOT USED */
  FETCHE_RANGE_ERROR,             /* 33 - RANGE "command" did not work */
  FETCHE_OBSOLETE34,              /* 34 */
  FETCHE_SSL_CONNECT_ERROR,       /* 35 - wrong when connecting with SSL */
  FETCHE_BAD_DOWNLOAD_RESUME,     /* 36 - could not resume download */
  FETCHE_FILE_COULDNT_READ_FILE,  /* 37 */
  FETCHE_LDAP_CANNOT_BIND,        /* 38 */
  FETCHE_LDAP_SEARCH_FAILED,      /* 39 */
  FETCHE_OBSOLETE40,              /* 40 - NOT USED */
  FETCHE_OBSOLETE41,              /* 41 - NOT USED starting with 7.53.0 */
  FETCHE_ABORTED_BY_CALLBACK,     /* 42 */
  FETCHE_BAD_FUNCTION_ARGUMENT,   /* 43 */
  FETCHE_OBSOLETE44,              /* 44 - NOT USED */
  FETCHE_INTERFACE_FAILED,        /* 45 - FETCHOPT_INTERFACE failed */
  FETCHE_OBSOLETE46,              /* 46 - NOT USED */
  FETCHE_TOO_MANY_REDIRECTS,      /* 47 - catch endless re-direct loops */
  FETCHE_UNKNOWN_OPTION,          /* 48 - User specified an unknown option */
  FETCHE_SETOPT_OPTION_SYNTAX,    /* 49 - Malformed setopt option */
  FETCHE_OBSOLETE50,              /* 50 - NOT USED */
  FETCHE_OBSOLETE51,              /* 51 - NOT USED */
  FETCHE_GOT_NOTHING,             /* 52 - when this is a specific error */
  FETCHE_SSL_ENGINE_NOTFOUND,     /* 53 - SSL crypto engine not found */
  FETCHE_SSL_ENGINE_SETFAILED,    /* 54 - can not set SSL crypto engine as
                                    default */
  FETCHE_SEND_ERROR,              /* 55 - failed sending network data */
  FETCHE_RECV_ERROR,              /* 56 - failure in receiving network data */
  FETCHE_OBSOLETE57,              /* 57 - NOT IN USE */
  FETCHE_SSL_CERTPROBLEM,         /* 58 - problem with the local certificate */
  FETCHE_SSL_CIPHER,              /* 59 - could not use specified cipher */
  FETCHE_PEER_FAILED_VERIFICATION, /* 60 - peer's certificate or fingerprint
                                     was not verified fine */
  FETCHE_BAD_CONTENT_ENCODING,    /* 61 - Unrecognized/bad encoding */
  FETCHE_OBSOLETE62,              /* 62 - NOT IN USE since 7.82.0 */
  FETCHE_FILESIZE_EXCEEDED,       /* 63 - Maximum file size exceeded */
  FETCHE_USE_SSL_FAILED,          /* 64 - Requested FTP SSL level failed */
  FETCHE_SEND_FAIL_REWIND,        /* 65 - Sending the data requires a rewind
                                    that failed */
  FETCHE_SSL_ENGINE_INITFAILED,   /* 66 - failed to initialise ENGINE */
  FETCHE_LOGIN_DENIED,            /* 67 - user, password or similar was not
                                    accepted and we failed to login */
  FETCHE_TFTP_NOTFOUND,           /* 68 - file not found on server */
  FETCHE_TFTP_PERM,               /* 69 - permission problem on server */
  FETCHE_REMOTE_DISK_FULL,        /* 70 - out of disk space on server */
  FETCHE_TFTP_ILLEGAL,            /* 71 - Illegal TFTP operation */
  FETCHE_TFTP_UNKNOWNID,          /* 72 - Unknown transfer ID */
  FETCHE_REMOTE_FILE_EXISTS,      /* 73 - File already exists */
  FETCHE_TFTP_NOSUCHUSER,         /* 74 - No such user */
  FETCHE_OBSOLETE75,              /* 75 - NOT IN USE since 7.82.0 */
  FETCHE_OBSOLETE76,              /* 76 - NOT IN USE since 7.82.0 */
  FETCHE_SSL_CACERT_BADFILE,      /* 77 - could not load CACERT file, missing
                                    or wrong format */
  FETCHE_REMOTE_FILE_NOT_FOUND,   /* 78 - remote file not found */
  FETCHE_SSH,                     /* 79 - error from the SSH layer, somewhat
                                    generic so the error message will be of
                                    interest when this has happened */

  FETCHE_SSL_SHUTDOWN_FAILED,     /* 80 - Failed to shut down the SSL
                                    connection */
  FETCHE_AGAIN,                   /* 81 - socket is not ready for send/recv,
                                    wait till it is ready and try again (Added
                                    in 7.18.2) */
  FETCHE_SSL_CRL_BADFILE,         /* 82 - could not load CRL file, missing or
                                    wrong format (Added in 7.19.0) */
  FETCHE_SSL_ISSUER_ERROR,        /* 83 - Issuer check failed.  (Added in
                                    7.19.0) */
  FETCHE_FTP_PRET_FAILED,         /* 84 - a PRET command failed */
  FETCHE_RTSP_CSEQ_ERROR,         /* 85 - mismatch of RTSP CSeq numbers */
  FETCHE_RTSP_SESSION_ERROR,      /* 86 - mismatch of RTSP Session Ids */
  FETCHE_FTP_BAD_FILE_LIST,       /* 87 - unable to parse FTP file list */
  FETCHE_CHUNK_FAILED,            /* 88 - chunk callback reported error */
  FETCHE_NO_CONNECTION_AVAILABLE, /* 89 - No connection available, the
                                    session will be queued */
  FETCHE_SSL_PINNEDPUBKEYNOTMATCH, /* 90 - specified pinned public key did not
                                     match */
  FETCHE_SSL_INVALIDCERTSTATUS,   /* 91 - invalid certificate status */
  FETCHE_HTTP2_STREAM,            /* 92 - stream error in HTTP/2 framing layer
                                    */
  FETCHE_RECURSIVE_API_CALL,      /* 93 - an api function was called from
                                    inside a callback */
  FETCHE_AUTH_ERROR,              /* 94 - an authentication function returned an
                                    error */
  FETCHE_HTTP3,                   /* 95 - An HTTP/3 layer problem */
  FETCHE_QUIC_CONNECT_ERROR,      /* 96 - QUIC connection error */
  FETCHE_PROXY,                   /* 97 - proxy handshake error */
  FETCHE_SSL_CLIENTCERT,          /* 98 - client-side certificate required */
  FETCHE_UNRECOVERABLE_POLL,      /* 99 - poll/select returned fatal error */
  FETCHE_TOO_LARGE,               /* 100 - a value/data met its maximum */
  FETCHE_ECH_REQUIRED,            /* 101 - ECH tried but failed */
  FETCH_LAST /* never use! */
} FETCHcode;

#ifndef FETCH_NO_OLDIES /* define this to test if your app builds with all
                          the obsolete stuff removed! */

/* removed in 7.53.0 */
#define FETCHE_FUNCTION_NOT_FOUND FETCHE_OBSOLETE41

/* removed in 7.56.0 */
#define FETCHE_HTTP_POST_ERROR FETCHE_OBSOLETE34

/* Previously obsolete error code reused in 7.38.0 */
#define FETCHE_OBSOLETE16 FETCHE_HTTP2

/* Previously obsolete error codes reused in 7.24.0 */
#define FETCHE_OBSOLETE10 FETCHE_FTP_ACCEPT_FAILED
#define FETCHE_OBSOLETE12 FETCHE_FTP_ACCEPT_TIMEOUT

/*  compatibility with older names */
#define FETCHOPT_ENCODING FETCHOPT_ACCEPT_ENCODING
#define FETCHE_FTP_WEIRD_SERVER_REPLY FETCHE_WEIRD_SERVER_REPLY

/* The following were added in 7.62.0 */
#define FETCHE_SSL_CACERT FETCHE_PEER_FAILED_VERIFICATION

/* The following were added in 7.21.5, April 2011 */
#define FETCHE_UNKNOWN_TELNET_OPTION FETCHE_UNKNOWN_OPTION

/* Added for 7.78.0 */
#define FETCHE_TELNET_OPTION_SYNTAX FETCHE_SETOPT_OPTION_SYNTAX

/* The following were added in 7.17.1 */
/* These are scheduled to disappear by 2009 */
#define FETCHE_SSL_PEER_CERTIFICATE FETCHE_PEER_FAILED_VERIFICATION

/* The following were added in 7.17.0 */
/* These are scheduled to disappear by 2009 */
#define FETCHE_OBSOLETE FETCHE_OBSOLETE50 /* no one should be using this! */
#define FETCHE_BAD_PASSWORD_ENTERED FETCHE_OBSOLETE46
#define FETCHE_BAD_CALLING_ORDER FETCHE_OBSOLETE44
#define FETCHE_FTP_USER_PASSWORD_INCORRECT FETCHE_OBSOLETE10
#define FETCHE_FTP_CANT_RECONNECT FETCHE_OBSOLETE16
#define FETCHE_FTP_COULDNT_GET_SIZE FETCHE_OBSOLETE32
#define FETCHE_FTP_COULDNT_SET_ASCII FETCHE_OBSOLETE29
#define FETCHE_FTP_WEIRD_USER_REPLY FETCHE_OBSOLETE12
#define FETCHE_FTP_WRITE_ERROR FETCHE_OBSOLETE20
#define FETCHE_LIBRARY_NOT_FOUND FETCHE_OBSOLETE40
#define FETCHE_MALFORMAT_USER FETCHE_OBSOLETE24
#define FETCHE_SHARE_IN_USE FETCHE_OBSOLETE57
#define FETCHE_URL_MALFORMAT_USER FETCHE_NOT_BUILT_IN

#define FETCHE_FTP_ACCESS_DENIED FETCHE_REMOTE_ACCESS_DENIED
#define FETCHE_FTP_COULDNT_SET_BINARY FETCHE_FTP_COULDNT_SET_TYPE
#define FETCHE_FTP_QUOTE_ERROR FETCHE_QUOTE_ERROR
#define FETCHE_TFTP_DISKFULL FETCHE_REMOTE_DISK_FULL
#define FETCHE_TFTP_EXISTS FETCHE_REMOTE_FILE_EXISTS
#define FETCHE_HTTP_RANGE_ERROR FETCHE_RANGE_ERROR
#define FETCHE_FTP_SSL_FAILED FETCHE_USE_SSL_FAILED

/* The following were added earlier */

#define FETCHE_OPERATION_TIMEOUTED FETCHE_OPERATION_TIMEDOUT
#define FETCHE_HTTP_NOT_FOUND FETCHE_HTTP_RETURNED_ERROR
#define FETCHE_HTTP_PORT_FAILED FETCHE_INTERFACE_FAILED
#define FETCHE_FTP_COULDNT_STOR_FILE FETCHE_UPLOAD_FAILED
#define FETCHE_FTP_PARTIAL_FILE FETCHE_PARTIAL_FILE
#define FETCHE_FTP_BAD_DOWNLOAD_RESUME FETCHE_BAD_DOWNLOAD_RESUME
#define FETCHE_LDAP_INVALID_URL FETCHE_OBSOLETE62
#define FETCHE_CONV_REQD FETCHE_OBSOLETE76
#define FETCHE_CONV_FAILED FETCHE_OBSOLETE75

/* This was the error code 50 in 7.7.3 and a few earlier versions, this
   is no longer used by libfetch but is instead #defined here only to not
   make programs break */
#define FETCHE_ALREADY_COMPLETE 99999

/* Provide defines for really old option names */
#define FETCHOPT_FILE FETCHOPT_WRITEDATA /* name changed in 7.9.7 */
#define FETCHOPT_INFILE FETCHOPT_READDATA /* name changed in 7.9.7 */
#define FETCHOPT_WRITEHEADER FETCHOPT_HEADERDATA

/* Since long deprecated options with no code in the lib that does anything
   with them. */
#define FETCHOPT_WRITEINFO FETCHOPT_OBSOLETE40
#define FETCHOPT_CLOSEPOLICY FETCHOPT_OBSOLETE72
#define FETCHOPT_OBSOLETE72 9999
#define FETCHOPT_OBSOLETE40 9999

#endif /* !FETCH_NO_OLDIES */

/*
 * Proxy error codes. Returned in FETCHINFO_PROXY_ERROR if FETCHE_PROXY was
 * return for the transfers.
 */
typedef enum {
  FETCHPX_OK,
  FETCHPX_BAD_ADDRESS_TYPE,
  FETCHPX_BAD_VERSION,
  FETCHPX_CLOSED,
  FETCHPX_GSSAPI,
  FETCHPX_GSSAPI_PERMSG,
  FETCHPX_GSSAPI_PROTECTION,
  FETCHPX_IDENTD,
  FETCHPX_IDENTD_DIFFER,
  FETCHPX_LONG_HOSTNAME,
  FETCHPX_LONG_PASSWD,
  FETCHPX_LONG_USER,
  FETCHPX_NO_AUTH,
  FETCHPX_RECV_ADDRESS,
  FETCHPX_RECV_AUTH,
  FETCHPX_RECV_CONNECT,
  FETCHPX_RECV_REQACK,
  FETCHPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
  FETCHPX_REPLY_COMMAND_NOT_SUPPORTED,
  FETCHPX_REPLY_CONNECTION_REFUSED,
  FETCHPX_REPLY_GENERAL_SERVER_FAILURE,
  FETCHPX_REPLY_HOST_UNREACHABLE,
  FETCHPX_REPLY_NETWORK_UNREACHABLE,
  FETCHPX_REPLY_NOT_ALLOWED,
  FETCHPX_REPLY_TTL_EXPIRED,
  FETCHPX_REPLY_UNASSIGNED,
  FETCHPX_REQUEST_FAILED,
  FETCHPX_RESOLVE_HOST,
  FETCHPX_SEND_AUTH,
  FETCHPX_SEND_CONNECT,
  FETCHPX_SEND_REQUEST,
  FETCHPX_UNKNOWN_FAIL,
  FETCHPX_UNKNOWN_MODE,
  FETCHPX_USER_REJECTED,
  FETCHPX_LAST /* never use */
} FETCHproxycode;

/* This prototype applies to all conversion callbacks */
typedef FETCHcode (*fetch_conv_callback)(char *buffer, size_t length);

typedef FETCHcode (*fetch_ssl_ctx_callback)(FETCH *fetch,    /* easy handle */
                                          void *ssl_ctx, /* actually an OpenSSL
                                                            or wolfSSL SSL_CTX,
                                                            or an mbedTLS
                                                          mbedtls_ssl_config */
                                          void *userptr);

typedef enum {
  FETCHPROXY_HTTP = 0,   /* added in 7.10, new in 7.19.4 default is to use
                           CONNECT HTTP/1.1 */
  FETCHPROXY_HTTP_1_0 = 1,   /* added in 7.19.4, force to use CONNECT
                               HTTP/1.0  */
  FETCHPROXY_HTTPS = 2,  /* HTTPS but stick to HTTP/1 added in 7.52.0 */
  FETCHPROXY_HTTPS2 = 3, /* HTTPS and attempt HTTP/2 added in 8.2.0 */
  FETCHPROXY_SOCKS4 = 4, /* support added in 7.15.2, enum existed already
                           in 7.10 */
  FETCHPROXY_SOCKS5 = 5, /* added in 7.10 */
  FETCHPROXY_SOCKS4A = 6, /* added in 7.18.0 */
  FETCHPROXY_SOCKS5_HOSTNAME = 7 /* Use the SOCKS5 protocol but pass along the
                                   hostname rather than the IP address. added
                                   in 7.18.0 */
} fetch_proxytype;  /* this enum was added in 7.10 */

/*
 * Bitmasks for FETCHOPT_HTTPAUTH and FETCHOPT_PROXYAUTH options:
 *
 * FETCHAUTH_NONE         - No HTTP authentication
 * FETCHAUTH_BASIC        - HTTP Basic authentication (default)
 * FETCHAUTH_DIGEST       - HTTP Digest authentication
 * FETCHAUTH_NEGOTIATE    - HTTP Negotiate (SPNEGO) authentication
 * FETCHAUTH_GSSNEGOTIATE - Alias for FETCHAUTH_NEGOTIATE (deprecated)
 * FETCHAUTH_NTLM         - HTTP NTLM authentication
 * FETCHAUTH_DIGEST_IE    - HTTP Digest authentication with IE flavour
 * FETCHAUTH_NTLM_WB      - HTTP NTLM authentication delegated to winbind helper
 * FETCHAUTH_BEARER       - HTTP Bearer token authentication
 * FETCHAUTH_ONLY         - Use together with a single other type to force no
 *                         authentication or just that single type
 * FETCHAUTH_ANY          - All fine types set
 * FETCHAUTH_ANYSAFE      - All fine types except Basic
 */

#define FETCHAUTH_NONE         ((unsigned long)0)
#define FETCHAUTH_BASIC        (((unsigned long)1)<<0)
#define FETCHAUTH_DIGEST       (((unsigned long)1)<<1)
#define FETCHAUTH_NEGOTIATE    (((unsigned long)1)<<2)
/* Deprecated since the advent of FETCHAUTH_NEGOTIATE */
#define FETCHAUTH_GSSNEGOTIATE FETCHAUTH_NEGOTIATE
/* Used for FETCHOPT_SOCKS5_AUTH to stay terminologically correct */
#define FETCHAUTH_GSSAPI FETCHAUTH_NEGOTIATE
#define FETCHAUTH_NTLM         (((unsigned long)1)<<3)
#define FETCHAUTH_DIGEST_IE    (((unsigned long)1)<<4)
#ifndef FETCH_NO_OLDIES
  /* functionality removed since 8.8.0 */
#define FETCHAUTH_NTLM_WB      (((unsigned long)1)<<5)
#endif
#define FETCHAUTH_BEARER       (((unsigned long)1)<<6)
#define FETCHAUTH_AWS_SIGV4    (((unsigned long)1)<<7)
#define FETCHAUTH_ONLY         (((unsigned long)1)<<31)
#define FETCHAUTH_ANY          (~FETCHAUTH_DIGEST_IE)
#define FETCHAUTH_ANYSAFE      (~(FETCHAUTH_BASIC|FETCHAUTH_DIGEST_IE))

#define FETCHSSH_AUTH_ANY       ~0     /* all types supported by the server */
#define FETCHSSH_AUTH_NONE      0      /* none allowed, silly but complete */
#define FETCHSSH_AUTH_PUBLICKEY (1<<0) /* public/private key files */
#define FETCHSSH_AUTH_PASSWORD  (1<<1) /* password */
#define FETCHSSH_AUTH_HOST      (1<<2) /* host key files */
#define FETCHSSH_AUTH_KEYBOARD  (1<<3) /* keyboard interactive */
#define FETCHSSH_AUTH_AGENT     (1<<4) /* agent (ssh-agent, pageant...) */
#define FETCHSSH_AUTH_GSSAPI    (1<<5) /* gssapi (kerberos, ...) */
#define FETCHSSH_AUTH_DEFAULT FETCHSSH_AUTH_ANY

#define FETCHGSSAPI_DELEGATION_NONE        0      /* no delegation (default) */
#define FETCHGSSAPI_DELEGATION_POLICY_FLAG (1<<0) /* if permitted by policy */
#define FETCHGSSAPI_DELEGATION_FLAG        (1<<1) /* delegate always */

#define FETCH_ERROR_SIZE 256

enum fetch_khtype {
  FETCHKHTYPE_UNKNOWN,
  FETCHKHTYPE_RSA1,
  FETCHKHTYPE_RSA,
  FETCHKHTYPE_DSS,
  FETCHKHTYPE_ECDSA,
  FETCHKHTYPE_ED25519
};

struct fetch_khkey {
  const char *key; /* points to a null-terminated string encoded with base64
                      if len is zero, otherwise to the "raw" data */
  size_t len;
  enum fetch_khtype keytype;
};

/* this is the set of return values expected from the fetch_sshkeycallback
   callback */
enum fetch_khstat {
  FETCHKHSTAT_FINE_ADD_TO_FILE,
  FETCHKHSTAT_FINE,
  FETCHKHSTAT_REJECT, /* reject the connection, return an error */
  FETCHKHSTAT_DEFER,  /* do not accept it, but we cannot answer right now.
                        Causes a FETCHE_PEER_FAILED_VERIFICATION error but the
                        connection will be left intact etc */
  FETCHKHSTAT_FINE_REPLACE, /* accept and replace the wrong key */
  FETCHKHSTAT_LAST    /* not for use, only a marker for last-in-list */
};

/* this is the set of status codes pass in to the callback */
enum fetch_khmatch {
  FETCHKHMATCH_OK,       /* match */
  FETCHKHMATCH_MISMATCH, /* host found, key mismatch! */
  FETCHKHMATCH_MISSING,  /* no matching host/key found */
  FETCHKHMATCH_LAST      /* not for use, only a marker for last-in-list */
};

typedef int
  (*fetch_sshkeycallback) (FETCH *easy,     /* easy handle */
                          const struct fetch_khkey *knownkey, /* known */
                          const struct fetch_khkey *foundkey, /* found */
                          enum fetch_khmatch, /* libfetch's view on the keys */
                          void *clientp); /* custom pointer passed with */
                                          /* FETCHOPT_SSH_KEYDATA */

typedef int
  (*fetch_sshhostkeycallback) (void *clientp,/* custom pointer passed */
                                            /* with FETCHOPT_SSH_HOSTKEYDATA */
                          int keytype, /* FETCHKHTYPE */
                          const char *key, /* hostkey to check */
                          size_t keylen); /* length of the key */
                          /* return FETCHE_OK to accept */
                          /* or something else to refuse */


/* parameter for the FETCHOPT_USE_SSL option */
typedef enum {
  FETCHUSESSL_NONE,    /* do not attempt to use SSL */
  FETCHUSESSL_TRY,     /* try using SSL, proceed anyway otherwise */
  FETCHUSESSL_CONTROL, /* SSL for the control connection or fail */
  FETCHUSESSL_ALL,     /* SSL for all communication or fail */
  FETCHUSESSL_LAST     /* not an option, never use */
} fetch_usessl;

/* Definition of bits for the FETCHOPT_SSL_OPTIONS argument: */

/* - ALLOW_BEAST tells libfetch to allow the BEAST SSL vulnerability in the
   name of improving interoperability with older servers. Some SSL libraries
   have introduced work-arounds for this flaw but those work-arounds sometimes
   make the SSL communication fail. To regain functionality with those broken
   servers, a user can this way allow the vulnerability back. */
#define FETCHSSLOPT_ALLOW_BEAST (1<<0)

/* - NO_REVOKE tells libfetch to disable certificate revocation checks for those
   SSL backends where such behavior is present. */
#define FETCHSSLOPT_NO_REVOKE (1<<1)

/* - NO_PARTIALCHAIN tells libfetch to *NOT* accept a partial certificate chain
   if possible. The OpenSSL backend has this ability. */
#define FETCHSSLOPT_NO_PARTIALCHAIN (1<<2)

/* - REVOKE_BEST_EFFORT tells libfetch to ignore certificate revocation offline
   checks and ignore missing revocation list for those SSL backends where such
   behavior is present. */
#define FETCHSSLOPT_REVOKE_BEST_EFFORT (1<<3)

/* - FETCHSSLOPT_NATIVE_CA tells libfetch to use standard certificate store of
   operating system. Currently implemented under MS-Windows. */
#define FETCHSSLOPT_NATIVE_CA (1<<4)

/* - FETCHSSLOPT_AUTO_CLIENT_CERT tells libfetch to automatically locate and use
   a client certificate for authentication. (Schannel) */
#define FETCHSSLOPT_AUTO_CLIENT_CERT (1<<5)

/* If possible, send data using TLS 1.3 early data */
#define FETCHSSLOPT_EARLYDATA (1<<6)

/* The default connection attempt delay in milliseconds for happy eyeballs.
   FETCHOPT_HAPPY_EYEBALLS_TIMEOUT_MS.3 and happy-eyeballs-timeout-ms.d document
   this value, keep them in sync. */
#define FETCH_HET_DEFAULT 200L

/* The default connection upkeep interval in milliseconds. */
#define FETCH_UPKEEP_INTERVAL_DEFAULT 60000L

#ifndef FETCH_NO_OLDIES /* define this to test if your app builds with all
                          the obsolete stuff removed! */

/* Backwards compatibility with older names */
/* These are scheduled to disappear by 2009 */

#define FETCHFTPSSL_NONE FETCHUSESSL_NONE
#define FETCHFTPSSL_TRY FETCHUSESSL_TRY
#define FETCHFTPSSL_CONTROL FETCHUSESSL_CONTROL
#define FETCHFTPSSL_ALL FETCHUSESSL_ALL
#define FETCHFTPSSL_LAST FETCHUSESSL_LAST
#define fetch_ftpssl fetch_usessl
#endif /* !FETCH_NO_OLDIES */

/* parameter for the FETCHOPT_FTP_SSL_CCC option */
typedef enum {
  FETCHFTPSSL_CCC_NONE,    /* do not send CCC */
  FETCHFTPSSL_CCC_PASSIVE, /* Let the server initiate the shutdown */
  FETCHFTPSSL_CCC_ACTIVE,  /* Initiate the shutdown */
  FETCHFTPSSL_CCC_LAST     /* not an option, never use */
} fetch_ftpccc;

/* parameter for the FETCHOPT_FTPSSLAUTH option */
typedef enum {
  FETCHFTPAUTH_DEFAULT, /* let libfetch decide */
  FETCHFTPAUTH_SSL,     /* use "AUTH SSL" */
  FETCHFTPAUTH_TLS,     /* use "AUTH TLS" */
  FETCHFTPAUTH_LAST /* not an option, never use */
} fetch_ftpauth;

/* parameter for the FETCHOPT_FTP_CREATE_MISSING_DIRS option */
typedef enum {
  FETCHFTP_CREATE_DIR_NONE,  /* do NOT create missing dirs! */
  FETCHFTP_CREATE_DIR,       /* (FTP/SFTP) if CWD fails, try MKD and then CWD
                               again if MKD succeeded, for SFTP this does
                               similar magic */
  FETCHFTP_CREATE_DIR_RETRY, /* (FTP only) if CWD fails, try MKD and then CWD
                               again even if MKD failed! */
  FETCHFTP_CREATE_DIR_LAST   /* not an option, never use */
} fetch_ftpcreatedir;

/* parameter for the FETCHOPT_FTP_FILEMETHOD option */
typedef enum {
  FETCHFTPMETHOD_DEFAULT,   /* let libfetch pick */
  FETCHFTPMETHOD_MULTICWD,  /* single CWD operation for each path part */
  FETCHFTPMETHOD_NOCWD,     /* no CWD at all */
  FETCHFTPMETHOD_SINGLECWD, /* one CWD to full dir, then work on file */
  FETCHFTPMETHOD_LAST       /* not an option, never use */
} fetch_ftpmethod;

/* bitmask defines for FETCHOPT_HEADEROPT */
#define FETCHHEADER_UNIFIED  0
#define FETCHHEADER_SEPARATE (1<<0)

/* FETCHALTSVC_* are bits for the FETCHOPT_ALTSVC_CTRL option */
#define FETCHALTSVC_READONLYFILE (1<<2)
#define FETCHALTSVC_H1           (1<<3)
#define FETCHALTSVC_H2           (1<<4)
#define FETCHALTSVC_H3           (1<<5)


struct fetch_hstsentry {
  char *name;
  size_t namelen;
  unsigned int includeSubDomains:1;
  char expire[18]; /* YYYYMMDD HH:MM:SS [null-terminated] */
};

struct fetch_index {
  size_t index; /* the provided entry's "index" or count */
  size_t total; /* total number of entries to save */
};

typedef enum {
  FETCHSTS_OK,
  FETCHSTS_DONE,
  FETCHSTS_FAIL
} FETCHSTScode;

typedef FETCHSTScode (*fetch_hstsread_callback)(FETCH *easy,
                                              struct fetch_hstsentry *e,
                                              void *userp);
typedef FETCHSTScode (*fetch_hstswrite_callback)(FETCH *easy,
                                               struct fetch_hstsentry *e,
                                               struct fetch_index *i,
                                               void *userp);

/* FETCHHSTS_* are bits for the FETCHOPT_HSTS option */
#define FETCHHSTS_ENABLE       (long)(1<<0)
#define FETCHHSTS_READONLYFILE (long)(1<<1)

/* The FETCHPROTO_ defines below are for the **deprecated** FETCHOPT_*PROTOCOLS
   options. Do not use. */
#define FETCHPROTO_HTTP   (1<<0)
#define FETCHPROTO_HTTPS  (1<<1)
#define FETCHPROTO_FTP    (1<<2)
#define FETCHPROTO_FTPS   (1<<3)
#define FETCHPROTO_SCP    (1<<4)
#define FETCHPROTO_SFTP   (1<<5)
#define FETCHPROTO_TELNET (1<<6)
#define FETCHPROTO_LDAP   (1<<7)
#define FETCHPROTO_LDAPS  (1<<8)
#define FETCHPROTO_DICT   (1<<9)
#define FETCHPROTO_FILE   (1<<10)
#define FETCHPROTO_TFTP   (1<<11)
#define FETCHPROTO_IMAP   (1<<12)
#define FETCHPROTO_IMAPS  (1<<13)
#define FETCHPROTO_POP3   (1<<14)
#define FETCHPROTO_POP3S  (1<<15)
#define FETCHPROTO_SMTP   (1<<16)
#define FETCHPROTO_SMTPS  (1<<17)
#define FETCHPROTO_RTSP   (1<<18)
#define FETCHPROTO_RTMP   (1<<19)
#define FETCHPROTO_RTMPT  (1<<20)
#define FETCHPROTO_RTMPE  (1<<21)
#define FETCHPROTO_RTMPTE (1<<22)
#define FETCHPROTO_RTMPS  (1<<23)
#define FETCHPROTO_RTMPTS (1<<24)
#define FETCHPROTO_GOPHER (1<<25)
#define FETCHPROTO_SMB    (1<<26)
#define FETCHPROTO_SMBS   (1<<27)
#define FETCHPROTO_MQTT   (1<<28)
#define FETCHPROTO_GOPHERS (1<<29)
#define FETCHPROTO_ALL    (~0) /* enable everything */

/* long may be 32 or 64 bits, but we should never depend on anything else
   but 32 */
#define FETCHOPTTYPE_LONG          0
#define FETCHOPTTYPE_OBJECTPOINT   10000
#define FETCHOPTTYPE_FUNCTIONPOINT 20000
#define FETCHOPTTYPE_OFF_T         30000
#define FETCHOPTTYPE_BLOB          40000

/* *STRINGPOINT is an alias for OBJECTPOINT to allow tools to extract the
   string options from the header file */


#define FETCHOPT(na,t,nu) na = t + nu
#define FETCHOPTDEPRECATED(na,t,nu,v,m) na FETCH_DEPRECATED(v,m) = t + nu

/* FETCHOPT aliases that make no runtime difference */

/* 'char *' argument to a string with a trailing zero */
#define FETCHOPTTYPE_STRINGPOINT FETCHOPTTYPE_OBJECTPOINT

/* 'struct fetch_slist *' argument */
#define FETCHOPTTYPE_SLISTPOINT  FETCHOPTTYPE_OBJECTPOINT

/* 'void *' argument passed untouched to callback */
#define FETCHOPTTYPE_CBPOINT     FETCHOPTTYPE_OBJECTPOINT

/* 'long' argument with a set of values/bitmask */
#define FETCHOPTTYPE_VALUES      FETCHOPTTYPE_LONG

/*
 * All FETCHOPT_* values.
 */

typedef enum {
  /* This is the FILE * or void * the regular output should be written to. */
  FETCHOPT(FETCHOPT_WRITEDATA, FETCHOPTTYPE_CBPOINT, 1),

  /* The full URL to get/put */
  FETCHOPT(FETCHOPT_URL, FETCHOPTTYPE_STRINGPOINT, 2),

  /* Port number to connect to, if other than default. */
  FETCHOPT(FETCHOPT_PORT, FETCHOPTTYPE_LONG, 3),

  /* Name of proxy to use. */
  FETCHOPT(FETCHOPT_PROXY, FETCHOPTTYPE_STRINGPOINT, 4),

  /* "user:password;options" to use when fetching. */
  FETCHOPT(FETCHOPT_USERPWD, FETCHOPTTYPE_STRINGPOINT, 5),

  /* "user:password" to use with proxy. */
  FETCHOPT(FETCHOPT_PROXYUSERPWD, FETCHOPTTYPE_STRINGPOINT, 6),

  /* Range to get, specified as an ASCII string. */
  FETCHOPT(FETCHOPT_RANGE, FETCHOPTTYPE_STRINGPOINT, 7),

  /* not used */

  /* Specified file stream to upload from (use as input): */
  FETCHOPT(FETCHOPT_READDATA, FETCHOPTTYPE_CBPOINT, 9),

  /* Buffer to receive error messages in, must be at least FETCH_ERROR_SIZE
   * bytes big. */
  FETCHOPT(FETCHOPT_ERRORBUFFER, FETCHOPTTYPE_OBJECTPOINT, 10),

  /* Function that will be called to store the output (instead of fwrite). The
   * parameters will use fwrite() syntax, make sure to follow them. */
  FETCHOPT(FETCHOPT_WRITEFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 11),

  /* Function that will be called to read the input (instead of fread). The
   * parameters will use fread() syntax, make sure to follow them. */
  FETCHOPT(FETCHOPT_READFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 12),

  /* Time-out the read operation after this amount of seconds */
  FETCHOPT(FETCHOPT_TIMEOUT, FETCHOPTTYPE_LONG, 13),

  /* If FETCHOPT_READDATA is used, this can be used to inform libfetch about
   * how large the file being sent really is. That allows better error
   * checking and better verifies that the upload was successful. -1 means
   * unknown size.
   *
   * For large file support, there is also a _LARGE version of the key
   * which takes an off_t type, allowing platforms with larger off_t
   * sizes to handle larger files. See below for INFILESIZE_LARGE.
   */
  FETCHOPT(FETCHOPT_INFILESIZE, FETCHOPTTYPE_LONG, 14),

  /* POST static input fields. */
  FETCHOPT(FETCHOPT_POSTFIELDS, FETCHOPTTYPE_OBJECTPOINT, 15),

  /* Set the referrer page (needed by some CGIs) */
  FETCHOPT(FETCHOPT_REFERER, FETCHOPTTYPE_STRINGPOINT, 16),

  /* Set the FTP PORT string (interface name, named or numerical IP address)
     Use i.e '-' to use default address. */
  FETCHOPT(FETCHOPT_FTPPORT, FETCHOPTTYPE_STRINGPOINT, 17),

  /* Set the User-Agent string (examined by some CGIs) */
  FETCHOPT(FETCHOPT_USERAGENT, FETCHOPTTYPE_STRINGPOINT, 18),

  /* If the download receives less than "low speed limit" bytes/second
   * during "low speed time" seconds, the operations is aborted.
   * You could i.e if you have a pretty high speed connection, abort if
   * it is less than 2000 bytes/sec during 20 seconds.
   */

  /* Set the "low speed limit" */
  FETCHOPT(FETCHOPT_LOW_SPEED_LIMIT, FETCHOPTTYPE_LONG, 19),

  /* Set the "low speed time" */
  FETCHOPT(FETCHOPT_LOW_SPEED_TIME, FETCHOPTTYPE_LONG, 20),

  /* Set the continuation offset.
   *
   * Note there is also a _LARGE version of this key which uses
   * off_t types, allowing for large file offsets on platforms which
   * use larger-than-32-bit off_t's. Look below for RESUME_FROM_LARGE.
   */
  FETCHOPT(FETCHOPT_RESUME_FROM, FETCHOPTTYPE_LONG, 21),

  /* Set cookie in request: */
  FETCHOPT(FETCHOPT_COOKIE, FETCHOPTTYPE_STRINGPOINT, 22),

  /* This points to a linked list of headers, struct fetch_slist kind. This
     list is also used for RTSP (in spite of its name) */
  FETCHOPT(FETCHOPT_HTTPHEADER, FETCHOPTTYPE_SLISTPOINT, 23),

  /* This points to a linked list of post entries, struct fetch_httppost */
  FETCHOPTDEPRECATED(FETCHOPT_HTTPPOST, FETCHOPTTYPE_OBJECTPOINT, 24,
                    7.56.0, "Use FETCHOPT_MIMEPOST"),

  /* name of the file keeping your private SSL-certificate */
  FETCHOPT(FETCHOPT_SSLCERT, FETCHOPTTYPE_STRINGPOINT, 25),

  /* password for the SSL or SSH private key */
  FETCHOPT(FETCHOPT_KEYPASSWD, FETCHOPTTYPE_STRINGPOINT, 26),

  /* send TYPE parameter? */
  FETCHOPT(FETCHOPT_CRLF, FETCHOPTTYPE_LONG, 27),

  /* send linked-list of QUOTE commands */
  FETCHOPT(FETCHOPT_QUOTE, FETCHOPTTYPE_SLISTPOINT, 28),

  /* send FILE * or void * to store headers to, if you use a callback it
     is simply passed to the callback unmodified */
  FETCHOPT(FETCHOPT_HEADERDATA, FETCHOPTTYPE_CBPOINT, 29),

  /* point to a file to read the initial cookies from, also enables
     "cookie awareness" */
  FETCHOPT(FETCHOPT_COOKIEFILE, FETCHOPTTYPE_STRINGPOINT, 31),

  /* What version to specifically try to use.
     See FETCH_SSLVERSION defines below. */
  FETCHOPT(FETCHOPT_SSLVERSION, FETCHOPTTYPE_VALUES, 32),

  /* What kind of HTTP time condition to use, see defines */
  FETCHOPT(FETCHOPT_TIMECONDITION, FETCHOPTTYPE_VALUES, 33),

  /* Time to use with the above condition. Specified in number of seconds
     since 1 Jan 1970 */
  FETCHOPT(FETCHOPT_TIMEVALUE, FETCHOPTTYPE_LONG, 34),

  /* 35 = OBSOLETE */

  /* Custom request, for customizing the get command like
     HTTP: DELETE, TRACE and others
     FTP: to use a different list command
     */
  FETCHOPT(FETCHOPT_CUSTOMREQUEST, FETCHOPTTYPE_STRINGPOINT, 36),

  /* FILE handle to use instead of stderr */
  FETCHOPT(FETCHOPT_STDERR, FETCHOPTTYPE_OBJECTPOINT, 37),

  /* 38 is not used */

  /* send linked-list of post-transfer QUOTE commands */
  FETCHOPT(FETCHOPT_POSTQUOTE, FETCHOPTTYPE_SLISTPOINT, 39),

  /* 40 is not used */

  /* talk a lot */
  FETCHOPT(FETCHOPT_VERBOSE, FETCHOPTTYPE_LONG, 41),

  /* throw the header out too */
  FETCHOPT(FETCHOPT_HEADER, FETCHOPTTYPE_LONG, 42),

  /* shut off the progress meter */
  FETCHOPT(FETCHOPT_NOPROGRESS, FETCHOPTTYPE_LONG, 43),

  /* use HEAD to get http document */
  FETCHOPT(FETCHOPT_NOBODY, FETCHOPTTYPE_LONG, 44),

  /* no output on http error codes >= 400 */
  FETCHOPT(FETCHOPT_FAILONERROR, FETCHOPTTYPE_LONG, 45),

  /* this is an upload */
  FETCHOPT(FETCHOPT_UPLOAD, FETCHOPTTYPE_LONG, 46),

  /* HTTP POST method */
  FETCHOPT(FETCHOPT_POST, FETCHOPTTYPE_LONG, 47),

  /* bare names when listing directories */
  FETCHOPT(FETCHOPT_DIRLISTONLY, FETCHOPTTYPE_LONG, 48),

  /* Append instead of overwrite on upload! */
  FETCHOPT(FETCHOPT_APPEND, FETCHOPTTYPE_LONG, 50),

  /* Specify whether to read the user+password from the .netrc or the URL.
   * This must be one of the FETCH_NETRC_* enums below. */
  FETCHOPT(FETCHOPT_NETRC, FETCHOPTTYPE_VALUES, 51),

  /* use Location: Luke! */
  FETCHOPT(FETCHOPT_FOLLOWLOCATION, FETCHOPTTYPE_LONG, 52),

   /* transfer data in text/ASCII format */
  FETCHOPT(FETCHOPT_TRANSFERTEXT, FETCHOPTTYPE_LONG, 53),

  /* HTTP PUT */
  FETCHOPTDEPRECATED(FETCHOPT_PUT, FETCHOPTTYPE_LONG, 54,
                    7.12.1, "Use FETCHOPT_UPLOAD"),

  /* 55 = OBSOLETE */

  /* DEPRECATED
   * Function that will be called instead of the internal progress display
   * function. This function should be defined as the fetch_progress_callback
   * prototype defines. */
  FETCHOPTDEPRECATED(FETCHOPT_PROGRESSFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 56,
                    7.32.0, "Use FETCHOPT_XFERINFOFUNCTION"),

  /* Data passed to the FETCHOPT_PROGRESSFUNCTION and FETCHOPT_XFERINFOFUNCTION
     callbacks */
  FETCHOPT(FETCHOPT_XFERINFODATA, FETCHOPTTYPE_CBPOINT, 57),
#define FETCHOPT_PROGRESSDATA FETCHOPT_XFERINFODATA

  /* We want the referrer field set automatically when following locations */
  FETCHOPT(FETCHOPT_AUTOREFERER, FETCHOPTTYPE_LONG, 58),

  /* Port of the proxy, can be set in the proxy string as well with:
     "[host]:[port]" */
  FETCHOPT(FETCHOPT_PROXYPORT, FETCHOPTTYPE_LONG, 59),

  /* size of the POST input data, if strlen() is not good to use */
  FETCHOPT(FETCHOPT_POSTFIELDSIZE, FETCHOPTTYPE_LONG, 60),

  /* tunnel non-http operations through an HTTP proxy */
  FETCHOPT(FETCHOPT_HTTPPROXYTUNNEL, FETCHOPTTYPE_LONG, 61),

  /* Set the interface string to use as outgoing network interface */
  FETCHOPT(FETCHOPT_INTERFACE, FETCHOPTTYPE_STRINGPOINT, 62),

  /* Set the krb4/5 security level, this also enables krb4/5 awareness. This
   * is a string, 'clear', 'safe', 'confidential' or 'private'. If the string
   * is set but does not match one of these, 'private' will be used.  */
  FETCHOPT(FETCHOPT_KRBLEVEL, FETCHOPTTYPE_STRINGPOINT, 63),

  /* Set if we should verify the peer in ssl handshake, set 1 to verify. */
  FETCHOPT(FETCHOPT_SSL_VERIFYPEER, FETCHOPTTYPE_LONG, 64),

  /* The CApath or CAfile used to validate the peer certificate
     this option is used only if SSL_VERIFYPEER is true */
  FETCHOPT(FETCHOPT_CAINFO, FETCHOPTTYPE_STRINGPOINT, 65),

  /* 66 = OBSOLETE */
  /* 67 = OBSOLETE */

  /* Maximum number of http redirects to follow */
  FETCHOPT(FETCHOPT_MAXREDIRS, FETCHOPTTYPE_LONG, 68),

  /* Pass a long set to 1 to get the date of the requested document (if
     possible)! Pass a zero to shut it off. */
  FETCHOPT(FETCHOPT_FILETIME, FETCHOPTTYPE_LONG, 69),

  /* This points to a linked list of telnet options */
  FETCHOPT(FETCHOPT_TELNETOPTIONS, FETCHOPTTYPE_SLISTPOINT, 70),

  /* Max amount of cached alive connections */
  FETCHOPT(FETCHOPT_MAXCONNECTS, FETCHOPTTYPE_LONG, 71),

  /* 72 = OBSOLETE */
  /* 73 = OBSOLETE */

  /* Set to explicitly use a new connection for the upcoming transfer.
     Do not use this unless you are absolutely sure of this, as it makes the
     operation slower and is less friendly for the network. */
  FETCHOPT(FETCHOPT_FRESH_CONNECT, FETCHOPTTYPE_LONG, 74),

  /* Set to explicitly forbid the upcoming transfer's connection to be reused
     when done. Do not use this unless you are absolutely sure of this, as it
     makes the operation slower and is less friendly for the network. */
  FETCHOPT(FETCHOPT_FORBID_REUSE, FETCHOPTTYPE_LONG, 75),

  /* Set to a filename that contains random data for libfetch to use to
     seed the random engine when doing SSL connects. */
  FETCHOPTDEPRECATED(FETCHOPT_RANDOM_FILE, FETCHOPTTYPE_STRINGPOINT, 76,
                    7.84.0, "Serves no purpose anymore"),

  /* Set to the Entropy Gathering Daemon socket pathname */
  FETCHOPTDEPRECATED(FETCHOPT_EGDSOCKET, FETCHOPTTYPE_STRINGPOINT, 77,
                    7.84.0, "Serves no purpose anymore"),

  /* Time-out connect operations after this amount of seconds, if connects are
     OK within this time, then fine... This only aborts the connect phase. */
  FETCHOPT(FETCHOPT_CONNECTTIMEOUT, FETCHOPTTYPE_LONG, 78),

  /* Function that will be called to store headers (instead of fwrite). The
   * parameters will use fwrite() syntax, make sure to follow them. */
  FETCHOPT(FETCHOPT_HEADERFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 79),

  /* Set this to force the HTTP request to get back to GET. Only really usable
     if POST, PUT or a custom request have been used first.
   */
  FETCHOPT(FETCHOPT_HTTPGET, FETCHOPTTYPE_LONG, 80),

  /* Set if we should verify the Common name from the peer certificate in ssl
   * handshake, set 1 to check existence, 2 to ensure that it matches the
   * provided hostname. */
  FETCHOPT(FETCHOPT_SSL_VERIFYHOST, FETCHOPTTYPE_LONG, 81),

  /* Specify which filename to write all known cookies in after completed
     operation. Set filename to "-" (dash) to make it go to stdout. */
  FETCHOPT(FETCHOPT_COOKIEJAR, FETCHOPTTYPE_STRINGPOINT, 82),

  /* Specify which TLS 1.2 (1.1, 1.0) ciphers to use */
  FETCHOPT(FETCHOPT_SSL_CIPHER_LIST, FETCHOPTTYPE_STRINGPOINT, 83),

  /* Specify which HTTP version to use! This must be set to one of the
     FETCH_HTTP_VERSION* enums set below. */
  FETCHOPT(FETCHOPT_HTTP_VERSION, FETCHOPTTYPE_VALUES, 84),

  /* Specifically switch on or off the FTP engine's use of the EPSV command. By
     default, that one will always be attempted before the more traditional
     PASV command. */
  FETCHOPT(FETCHOPT_FTP_USE_EPSV, FETCHOPTTYPE_LONG, 85),

  /* type of the file keeping your SSL-certificate ("DER", "PEM", "ENG") */
  FETCHOPT(FETCHOPT_SSLCERTTYPE, FETCHOPTTYPE_STRINGPOINT, 86),

  /* name of the file keeping your private SSL-key */
  FETCHOPT(FETCHOPT_SSLKEY, FETCHOPTTYPE_STRINGPOINT, 87),

  /* type of the file keeping your private SSL-key ("DER", "PEM", "ENG") */
  FETCHOPT(FETCHOPT_SSLKEYTYPE, FETCHOPTTYPE_STRINGPOINT, 88),

  /* crypto engine for the SSL-sub system */
  FETCHOPT(FETCHOPT_SSLENGINE, FETCHOPTTYPE_STRINGPOINT, 89),

  /* set the crypto engine for the SSL-sub system as default
     the param has no meaning...
   */
  FETCHOPT(FETCHOPT_SSLENGINE_DEFAULT, FETCHOPTTYPE_LONG, 90),

  /* Non-zero value means to use the global dns cache */
  /* DEPRECATED, do not use! */
  FETCHOPTDEPRECATED(FETCHOPT_DNS_USE_GLOBAL_CACHE, FETCHOPTTYPE_LONG, 91,
                    7.11.1, "Use FETCHOPT_SHARE"),

  /* DNS cache timeout */
  FETCHOPT(FETCHOPT_DNS_CACHE_TIMEOUT, FETCHOPTTYPE_LONG, 92),

  /* send linked-list of pre-transfer QUOTE commands */
  FETCHOPT(FETCHOPT_PREQUOTE, FETCHOPTTYPE_SLISTPOINT, 93),

  /* set the debug function */
  FETCHOPT(FETCHOPT_DEBUGFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 94),

  /* set the data for the debug function */
  FETCHOPT(FETCHOPT_DEBUGDATA, FETCHOPTTYPE_CBPOINT, 95),

  /* mark this as start of a cookie session */
  FETCHOPT(FETCHOPT_COOKIESESSION, FETCHOPTTYPE_LONG, 96),

  /* The CApath directory used to validate the peer certificate
     this option is used only if SSL_VERIFYPEER is true */
  FETCHOPT(FETCHOPT_CAPATH, FETCHOPTTYPE_STRINGPOINT, 97),

  /* Instruct libfetch to use a smaller receive buffer */
  FETCHOPT(FETCHOPT_BUFFERSIZE, FETCHOPTTYPE_LONG, 98),

  /* Instruct libfetch to not use any signal/alarm handlers, even when using
     timeouts. This option is useful for multi-threaded applications.
     See libfetch-the-guide for more background information. */
  FETCHOPT(FETCHOPT_NOSIGNAL, FETCHOPTTYPE_LONG, 99),

  /* Provide a FETCHShare for mutexing non-ts data */
  FETCHOPT(FETCHOPT_SHARE, FETCHOPTTYPE_OBJECTPOINT, 100),

  /* indicates type of proxy. accepted values are FETCHPROXY_HTTP (default),
     FETCHPROXY_HTTPS, FETCHPROXY_SOCKS4, FETCHPROXY_SOCKS4A and
     FETCHPROXY_SOCKS5. */
  FETCHOPT(FETCHOPT_PROXYTYPE, FETCHOPTTYPE_VALUES, 101),

  /* Set the Accept-Encoding string. Use this to tell a server you would like
     the response to be compressed. Before 7.21.6, this was known as
     FETCHOPT_ENCODING */
  FETCHOPT(FETCHOPT_ACCEPT_ENCODING, FETCHOPTTYPE_STRINGPOINT, 102),

  /* Set pointer to private data */
  FETCHOPT(FETCHOPT_PRIVATE, FETCHOPTTYPE_OBJECTPOINT, 103),

  /* Set aliases for HTTP 200 in the HTTP Response header */
  FETCHOPT(FETCHOPT_HTTP200ALIASES, FETCHOPTTYPE_SLISTPOINT, 104),

  /* Continue to send authentication (user+password) when following locations,
     even when hostname changed. This can potentially send off the name
     and password to whatever host the server decides. */
  FETCHOPT(FETCHOPT_UNRESTRICTED_AUTH, FETCHOPTTYPE_LONG, 105),

  /* Specifically switch on or off the FTP engine's use of the EPRT command (
     it also disables the LPRT attempt). By default, those ones will always be
     attempted before the good old traditional PORT command. */
  FETCHOPT(FETCHOPT_FTP_USE_EPRT, FETCHOPTTYPE_LONG, 106),

  /* Set this to a bitmask value to enable the particular authentications
     methods you like. Use this in combination with FETCHOPT_USERPWD.
     Note that setting multiple bits may cause extra network round-trips. */
  FETCHOPT(FETCHOPT_HTTPAUTH, FETCHOPTTYPE_VALUES, 107),

  /* Set the ssl context callback function, currently only for OpenSSL or
     wolfSSL ssl_ctx, or mbedTLS mbedtls_ssl_config in the second argument.
     The function must match the fetch_ssl_ctx_callback prototype. */
  FETCHOPT(FETCHOPT_SSL_CTX_FUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 108),

  /* Set the userdata for the ssl context callback function's third
     argument */
  FETCHOPT(FETCHOPT_SSL_CTX_DATA, FETCHOPTTYPE_CBPOINT, 109),

  /* FTP Option that causes missing dirs to be created on the remote server.
     In 7.19.4 we introduced the convenience enums for this option using the
     FETCHFTP_CREATE_DIR prefix.
  */
  FETCHOPT(FETCHOPT_FTP_CREATE_MISSING_DIRS, FETCHOPTTYPE_LONG, 110),

  /* Set this to a bitmask value to enable the particular authentications
     methods you like. Use this in combination with FETCHOPT_PROXYUSERPWD.
     Note that setting multiple bits may cause extra network round-trips. */
  FETCHOPT(FETCHOPT_PROXYAUTH, FETCHOPTTYPE_VALUES, 111),

  /* Option that changes the timeout, in seconds, associated with getting a
     response. This is different from transfer timeout time and essentially
     places a demand on the server to acknowledge commands in a timely
     manner. For FTP, SMTP, IMAP and POP3. */
  FETCHOPT(FETCHOPT_SERVER_RESPONSE_TIMEOUT, FETCHOPTTYPE_LONG, 112),

  /* Set this option to one of the FETCH_IPRESOLVE_* defines (see below) to
     tell libfetch to use those IP versions only. This only has effect on
     systems with support for more than one, i.e IPv4 _and_ IPv6. */
  FETCHOPT(FETCHOPT_IPRESOLVE, FETCHOPTTYPE_VALUES, 113),

  /* Set this option to limit the size of a file that will be downloaded from
     an HTTP or FTP server.

     Note there is also _LARGE version which adds large file support for
     platforms which have larger off_t sizes. See MAXFILESIZE_LARGE below. */
  FETCHOPT(FETCHOPT_MAXFILESIZE, FETCHOPTTYPE_LONG, 114),

  /* See the comment for INFILESIZE above, but in short, specifies
   * the size of the file being uploaded.  -1 means unknown.
   */
  FETCHOPT(FETCHOPT_INFILESIZE_LARGE, FETCHOPTTYPE_OFF_T, 115),

  /* Sets the continuation offset. There is also a FETCHOPTTYPE_LONG version
   * of this; look above for RESUME_FROM.
   */
  FETCHOPT(FETCHOPT_RESUME_FROM_LARGE, FETCHOPTTYPE_OFF_T, 116),

  /* Sets the maximum size of data that will be downloaded from
   * an HTTP or FTP server. See MAXFILESIZE above for the LONG version.
   */
  FETCHOPT(FETCHOPT_MAXFILESIZE_LARGE, FETCHOPTTYPE_OFF_T, 117),

  /* Set this option to the filename of your .netrc file you want libfetch
     to parse (using the FETCHOPT_NETRC option). If not set, libfetch will do
     a poor attempt to find the user's home directory and check for a .netrc
     file in there. */
  FETCHOPT(FETCHOPT_NETRC_FILE, FETCHOPTTYPE_STRINGPOINT, 118),

  /* Enable SSL/TLS for FTP, pick one of:
     FETCHUSESSL_TRY     - try using SSL, proceed anyway otherwise
     FETCHUSESSL_CONTROL - SSL for the control connection or fail
     FETCHUSESSL_ALL     - SSL for all communication or fail
  */
  FETCHOPT(FETCHOPT_USE_SSL, FETCHOPTTYPE_VALUES, 119),

  /* The _LARGE version of the standard POSTFIELDSIZE option */
  FETCHOPT(FETCHOPT_POSTFIELDSIZE_LARGE, FETCHOPTTYPE_OFF_T, 120),

  /* Enable/disable the TCP Nagle algorithm */
  FETCHOPT(FETCHOPT_TCP_NODELAY, FETCHOPTTYPE_LONG, 121),

  /* 122 OBSOLETE, used in 7.12.3. Gone in 7.13.0 */
  /* 123 OBSOLETE. Gone in 7.16.0 */
  /* 124 OBSOLETE, used in 7.12.3. Gone in 7.13.0 */
  /* 125 OBSOLETE, used in 7.12.3. Gone in 7.13.0 */
  /* 126 OBSOLETE, used in 7.12.3. Gone in 7.13.0 */
  /* 127 OBSOLETE. Gone in 7.16.0 */
  /* 128 OBSOLETE. Gone in 7.16.0 */

  /* When FTP over SSL/TLS is selected (with FETCHOPT_USE_SSL), this option
     can be used to change libfetch's default action which is to first try
     "AUTH SSL" and then "AUTH TLS" in this order, and proceed when a OK
     response has been received.

     Available parameters are:
     FETCHFTPAUTH_DEFAULT - let libfetch decide
     FETCHFTPAUTH_SSL     - try "AUTH SSL" first, then TLS
     FETCHFTPAUTH_TLS     - try "AUTH TLS" first, then SSL
  */
  FETCHOPT(FETCHOPT_FTPSSLAUTH, FETCHOPTTYPE_VALUES, 129),

  FETCHOPTDEPRECATED(FETCHOPT_IOCTLFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 130,
                    7.18.0, "Use FETCHOPT_SEEKFUNCTION"),
  FETCHOPTDEPRECATED(FETCHOPT_IOCTLDATA, FETCHOPTTYPE_CBPOINT, 131,
                    7.18.0, "Use FETCHOPT_SEEKDATA"),

  /* 132 OBSOLETE. Gone in 7.16.0 */
  /* 133 OBSOLETE. Gone in 7.16.0 */

  /* null-terminated string for pass on to the FTP server when asked for
     "account" info */
  FETCHOPT(FETCHOPT_FTP_ACCOUNT, FETCHOPTTYPE_STRINGPOINT, 134),

  /* feed cookie into cookie engine */
  FETCHOPT(FETCHOPT_COOKIELIST, FETCHOPTTYPE_STRINGPOINT, 135),

  /* ignore Content-Length */
  FETCHOPT(FETCHOPT_IGNORE_CONTENT_LENGTH, FETCHOPTTYPE_LONG, 136),

  /* Set to non-zero to skip the IP address received in a 227 PASV FTP server
     response. Typically used for FTP-SSL purposes but is not restricted to
     that. libfetch will then instead use the same IP address it used for the
     control connection. */
  FETCHOPT(FETCHOPT_FTP_SKIP_PASV_IP, FETCHOPTTYPE_LONG, 137),

  /* Select "file method" to use when doing FTP, see the fetch_ftpmethod
     above. */
  FETCHOPT(FETCHOPT_FTP_FILEMETHOD, FETCHOPTTYPE_VALUES, 138),

  /* Local port number to bind the socket to */
  FETCHOPT(FETCHOPT_LOCALPORT, FETCHOPTTYPE_LONG, 139),

  /* Number of ports to try, including the first one set with LOCALPORT.
     Thus, setting it to 1 will make no additional attempts but the first.
  */
  FETCHOPT(FETCHOPT_LOCALPORTRANGE, FETCHOPTTYPE_LONG, 140),

  /* no transfer, set up connection and let application use the socket by
     extracting it with FETCHINFO_LASTSOCKET */
  FETCHOPT(FETCHOPT_CONNECT_ONLY, FETCHOPTTYPE_LONG, 141),

  /* Function that will be called to convert from the
     network encoding (instead of using the iconv calls in libfetch) */
  FETCHOPTDEPRECATED(FETCHOPT_CONV_FROM_NETWORK_FUNCTION,
                    FETCHOPTTYPE_FUNCTIONPOINT, 142,
                    7.82.0, "Serves no purpose anymore"),

  /* Function that will be called to convert to the
     network encoding (instead of using the iconv calls in libfetch) */
  FETCHOPTDEPRECATED(FETCHOPT_CONV_TO_NETWORK_FUNCTION,
                    FETCHOPTTYPE_FUNCTIONPOINT, 143,
                    7.82.0, "Serves no purpose anymore"),

  /* Function that will be called to convert from UTF8
     (instead of using the iconv calls in libfetch)
     Note that this is used only for SSL certificate processing */
  FETCHOPTDEPRECATED(FETCHOPT_CONV_FROM_UTF8_FUNCTION,
                    FETCHOPTTYPE_FUNCTIONPOINT, 144,
                    7.82.0, "Serves no purpose anymore"),

  /* if the connection proceeds too quickly then need to slow it down */
  /* limit-rate: maximum number of bytes per second to send or receive */
  FETCHOPT(FETCHOPT_MAX_SEND_SPEED_LARGE, FETCHOPTTYPE_OFF_T, 145),
  FETCHOPT(FETCHOPT_MAX_RECV_SPEED_LARGE, FETCHOPTTYPE_OFF_T, 146),

  /* Pointer to command string to send if USER/PASS fails. */
  FETCHOPT(FETCHOPT_FTP_ALTERNATIVE_TO_USER, FETCHOPTTYPE_STRINGPOINT, 147),

  /* callback function for setting socket options */
  FETCHOPT(FETCHOPT_SOCKOPTFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 148),
  FETCHOPT(FETCHOPT_SOCKOPTDATA, FETCHOPTTYPE_CBPOINT, 149),

  /* set to 0 to disable session ID reuse for this transfer, default is
     enabled (== 1) */
  FETCHOPT(FETCHOPT_SSL_SESSIONID_CACHE, FETCHOPTTYPE_LONG, 150),

  /* allowed SSH authentication methods */
  FETCHOPT(FETCHOPT_SSH_AUTH_TYPES, FETCHOPTTYPE_VALUES, 151),

  /* Used by scp/sftp to do public/private key authentication */
  FETCHOPT(FETCHOPT_SSH_PUBLIC_KEYFILE, FETCHOPTTYPE_STRINGPOINT, 152),
  FETCHOPT(FETCHOPT_SSH_PRIVATE_KEYFILE, FETCHOPTTYPE_STRINGPOINT, 153),

  /* Send CCC (Clear Command Channel) after authentication */
  FETCHOPT(FETCHOPT_FTP_SSL_CCC, FETCHOPTTYPE_LONG, 154),

  /* Same as TIMEOUT and CONNECTTIMEOUT, but with ms resolution */
  FETCHOPT(FETCHOPT_TIMEOUT_MS, FETCHOPTTYPE_LONG, 155),
  FETCHOPT(FETCHOPT_CONNECTTIMEOUT_MS, FETCHOPTTYPE_LONG, 156),

  /* set to zero to disable the libfetch's decoding and thus pass the raw body
     data to the application even when it is encoded/compressed */
  FETCHOPT(FETCHOPT_HTTP_TRANSFER_DECODING, FETCHOPTTYPE_LONG, 157),
  FETCHOPT(FETCHOPT_HTTP_CONTENT_DECODING, FETCHOPTTYPE_LONG, 158),

  /* Permission used when creating new files and directories on the remote
     server for protocols that support it, SFTP/SCP/FILE */
  FETCHOPT(FETCHOPT_NEW_FILE_PERMS, FETCHOPTTYPE_LONG, 159),
  FETCHOPT(FETCHOPT_NEW_DIRECTORY_PERMS, FETCHOPTTYPE_LONG, 160),

  /* Set the behavior of POST when redirecting. Values must be set to one
     of FETCH_REDIR* defines below. This used to be called FETCHOPT_POST301 */
  FETCHOPT(FETCHOPT_POSTREDIR, FETCHOPTTYPE_VALUES, 161),

  /* used by scp/sftp to verify the host's public key */
  FETCHOPT(FETCHOPT_SSH_HOST_PUBLIC_KEY_MD5, FETCHOPTTYPE_STRINGPOINT, 162),

  /* Callback function for opening socket (instead of socket(2)). Optionally,
     callback is able change the address or refuse to connect returning
     FETCH_SOCKET_BAD. The callback should have type
     fetch_opensocket_callback */
  FETCHOPT(FETCHOPT_OPENSOCKETFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 163),
  FETCHOPT(FETCHOPT_OPENSOCKETDATA, FETCHOPTTYPE_CBPOINT, 164),

  /* POST volatile input fields. */
  FETCHOPT(FETCHOPT_COPYPOSTFIELDS, FETCHOPTTYPE_OBJECTPOINT, 165),

  /* set transfer mode (;type=<a|i>) when doing FTP via an HTTP proxy */
  FETCHOPT(FETCHOPT_PROXY_TRANSFER_MODE, FETCHOPTTYPE_LONG, 166),

  /* Callback function for seeking in the input stream */
  FETCHOPT(FETCHOPT_SEEKFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 167),
  FETCHOPT(FETCHOPT_SEEKDATA, FETCHOPTTYPE_CBPOINT, 168),

  /* CRL file */
  FETCHOPT(FETCHOPT_CRLFILE, FETCHOPTTYPE_STRINGPOINT, 169),

  /* Issuer certificate */
  FETCHOPT(FETCHOPT_ISSUERCERT, FETCHOPTTYPE_STRINGPOINT, 170),

  /* (IPv6) Address scope */
  FETCHOPT(FETCHOPT_ADDRESS_SCOPE, FETCHOPTTYPE_LONG, 171),

  /* Collect certificate chain info and allow it to get retrievable with
     FETCHINFO_CERTINFO after the transfer is complete. */
  FETCHOPT(FETCHOPT_CERTINFO, FETCHOPTTYPE_LONG, 172),

  /* "name" and "pwd" to use when fetching. */
  FETCHOPT(FETCHOPT_USERNAME, FETCHOPTTYPE_STRINGPOINT, 173),
  FETCHOPT(FETCHOPT_PASSWORD, FETCHOPTTYPE_STRINGPOINT, 174),

    /* "name" and "pwd" to use with Proxy when fetching. */
  FETCHOPT(FETCHOPT_PROXYUSERNAME, FETCHOPTTYPE_STRINGPOINT, 175),
  FETCHOPT(FETCHOPT_PROXYPASSWORD, FETCHOPTTYPE_STRINGPOINT, 176),

  /* Comma separated list of hostnames defining no-proxy zones. These should
     match both hostnames directly, and hostnames within a domain. For
     example, local.com will match local.com and www.local.com, but NOT
     notlocal.com or www.notlocal.com. For compatibility with other
     implementations of this, .local.com will be considered to be the same as
     local.com. A single * is the only valid wildcard, and effectively
     disables the use of proxy. */
  FETCHOPT(FETCHOPT_NOPROXY, FETCHOPTTYPE_STRINGPOINT, 177),

  /* block size for TFTP transfers */
  FETCHOPT(FETCHOPT_TFTP_BLKSIZE, FETCHOPTTYPE_LONG, 178),

  /* Socks Service */
  /* DEPRECATED, do not use! */
  FETCHOPTDEPRECATED(FETCHOPT_SOCKS5_GSSAPI_SERVICE,
                    FETCHOPTTYPE_STRINGPOINT, 179,
                    7.49.0, "Use FETCHOPT_PROXY_SERVICE_NAME"),

  /* Socks Service */
  FETCHOPT(FETCHOPT_SOCKS5_GSSAPI_NEC, FETCHOPTTYPE_LONG, 180),

  /* set the bitmask for the protocols that are allowed to be used for the
     transfer, which thus helps the app which takes URLs from users or other
     external inputs and want to restrict what protocol(s) to deal
     with. Defaults to FETCHPROTO_ALL. */
  FETCHOPTDEPRECATED(FETCHOPT_PROTOCOLS, FETCHOPTTYPE_LONG, 181,
                    7.85.0, "Use FETCHOPT_PROTOCOLS_STR"),

  /* set the bitmask for the protocols that libfetch is allowed to follow to,
     as a subset of the FETCHOPT_PROTOCOLS ones. That means the protocol needs
     to be set in both bitmasks to be allowed to get redirected to. */
  FETCHOPTDEPRECATED(FETCHOPT_REDIR_PROTOCOLS, FETCHOPTTYPE_LONG, 182,
                    7.85.0, "Use FETCHOPT_REDIR_PROTOCOLS_STR"),

  /* set the SSH knownhost filename to use */
  FETCHOPT(FETCHOPT_SSH_KNOWNHOSTS, FETCHOPTTYPE_STRINGPOINT, 183),

  /* set the SSH host key callback, must point to a fetch_sshkeycallback
     function */
  FETCHOPT(FETCHOPT_SSH_KEYFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 184),

  /* set the SSH host key callback custom pointer */
  FETCHOPT(FETCHOPT_SSH_KEYDATA, FETCHOPTTYPE_CBPOINT, 185),

  /* set the SMTP mail originator */
  FETCHOPT(FETCHOPT_MAIL_FROM, FETCHOPTTYPE_STRINGPOINT, 186),

  /* set the list of SMTP mail receiver(s) */
  FETCHOPT(FETCHOPT_MAIL_RCPT, FETCHOPTTYPE_SLISTPOINT, 187),

  /* FTP: send PRET before PASV */
  FETCHOPT(FETCHOPT_FTP_USE_PRET, FETCHOPTTYPE_LONG, 188),

  /* RTSP request method (OPTIONS, SETUP, PLAY, etc...) */
  FETCHOPT(FETCHOPT_RTSP_REQUEST, FETCHOPTTYPE_VALUES, 189),

  /* The RTSP session identifier */
  FETCHOPT(FETCHOPT_RTSP_SESSION_ID, FETCHOPTTYPE_STRINGPOINT, 190),

  /* The RTSP stream URI */
  FETCHOPT(FETCHOPT_RTSP_STREAM_URI, FETCHOPTTYPE_STRINGPOINT, 191),

  /* The Transport: header to use in RTSP requests */
  FETCHOPT(FETCHOPT_RTSP_TRANSPORT, FETCHOPTTYPE_STRINGPOINT, 192),

  /* Manually initialize the client RTSP CSeq for this handle */
  FETCHOPT(FETCHOPT_RTSP_CLIENT_CSEQ, FETCHOPTTYPE_LONG, 193),

  /* Manually initialize the server RTSP CSeq for this handle */
  FETCHOPT(FETCHOPT_RTSP_SERVER_CSEQ, FETCHOPTTYPE_LONG, 194),

  /* The stream to pass to INTERLEAVEFUNCTION. */
  FETCHOPT(FETCHOPT_INTERLEAVEDATA, FETCHOPTTYPE_CBPOINT, 195),

  /* Let the application define a custom write method for RTP data */
  FETCHOPT(FETCHOPT_INTERLEAVEFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 196),

  /* Turn on wildcard matching */
  FETCHOPT(FETCHOPT_WILDCARDMATCH, FETCHOPTTYPE_LONG, 197),

  /* Directory matching callback called before downloading of an
     individual file (chunk) started */
  FETCHOPT(FETCHOPT_CHUNK_BGN_FUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 198),

  /* Directory matching callback called after the file (chunk)
     was downloaded, or skipped */
  FETCHOPT(FETCHOPT_CHUNK_END_FUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 199),

  /* Change match (fnmatch-like) callback for wildcard matching */
  FETCHOPT(FETCHOPT_FNMATCH_FUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 200),

  /* Let the application define custom chunk data pointer */
  FETCHOPT(FETCHOPT_CHUNK_DATA, FETCHOPTTYPE_CBPOINT, 201),

  /* FNMATCH_FUNCTION user pointer */
  FETCHOPT(FETCHOPT_FNMATCH_DATA, FETCHOPTTYPE_CBPOINT, 202),

  /* send linked-list of name:port:address sets */
  FETCHOPT(FETCHOPT_RESOLVE, FETCHOPTTYPE_SLISTPOINT, 203),

  /* Set a username for authenticated TLS */
  FETCHOPT(FETCHOPT_TLSAUTH_USERNAME, FETCHOPTTYPE_STRINGPOINT, 204),

  /* Set a password for authenticated TLS */
  FETCHOPT(FETCHOPT_TLSAUTH_PASSWORD, FETCHOPTTYPE_STRINGPOINT, 205),

  /* Set authentication type for authenticated TLS */
  FETCHOPT(FETCHOPT_TLSAUTH_TYPE, FETCHOPTTYPE_STRINGPOINT, 206),

  /* Set to 1 to enable the "TE:" header in HTTP requests to ask for
     compressed transfer-encoded responses. Set to 0 to disable the use of TE:
     in outgoing requests. The current default is 0, but it might change in a
     future libfetch release.

     libfetch will ask for the compressed methods it knows of, and if that
     is not any, it will not ask for transfer-encoding at all even if this
     option is set to 1.

  */
  FETCHOPT(FETCHOPT_TRANSFER_ENCODING, FETCHOPTTYPE_LONG, 207),

  /* Callback function for closing socket (instead of close(2)). The callback
     should have type fetch_closesocket_callback */
  FETCHOPT(FETCHOPT_CLOSESOCKETFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 208),
  FETCHOPT(FETCHOPT_CLOSESOCKETDATA, FETCHOPTTYPE_CBPOINT, 209),

  /* allow GSSAPI credential delegation */
  FETCHOPT(FETCHOPT_GSSAPI_DELEGATION, FETCHOPTTYPE_VALUES, 210),

  /* Set the name servers to use for DNS resolution.
   * Only supported by the c-ares DNS backend */
  FETCHOPT(FETCHOPT_DNS_SERVERS, FETCHOPTTYPE_STRINGPOINT, 211),

  /* Time-out accept operations (currently for FTP only) after this amount
     of milliseconds. */
  FETCHOPT(FETCHOPT_ACCEPTTIMEOUT_MS, FETCHOPTTYPE_LONG, 212),

  /* Set TCP keepalive */
  FETCHOPT(FETCHOPT_TCP_KEEPALIVE, FETCHOPTTYPE_LONG, 213),

  /* non-universal keepalive knobs (Linux, AIX, HP-UX, more) */
  FETCHOPT(FETCHOPT_TCP_KEEPIDLE, FETCHOPTTYPE_LONG, 214),
  FETCHOPT(FETCHOPT_TCP_KEEPINTVL, FETCHOPTTYPE_LONG, 215),

  /* Enable/disable specific SSL features with a bitmask, see FETCHSSLOPT_* */
  FETCHOPT(FETCHOPT_SSL_OPTIONS, FETCHOPTTYPE_VALUES, 216),

  /* Set the SMTP auth originator */
  FETCHOPT(FETCHOPT_MAIL_AUTH, FETCHOPTTYPE_STRINGPOINT, 217),

  /* Enable/disable SASL initial response */
  FETCHOPT(FETCHOPT_SASL_IR, FETCHOPTTYPE_LONG, 218),

  /* Function that will be called instead of the internal progress display
   * function. This function should be defined as the fetch_xferinfo_callback
   * prototype defines. (Deprecates FETCHOPT_PROGRESSFUNCTION) */
  FETCHOPT(FETCHOPT_XFERINFOFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 219),

  /* The XOAUTH2 bearer token */
  FETCHOPT(FETCHOPT_XOAUTH2_BEARER, FETCHOPTTYPE_STRINGPOINT, 220),

  /* Set the interface string to use as outgoing network
   * interface for DNS requests.
   * Only supported by the c-ares DNS backend */
  FETCHOPT(FETCHOPT_DNS_INTERFACE, FETCHOPTTYPE_STRINGPOINT, 221),

  /* Set the local IPv4 address to use for outgoing DNS requests.
   * Only supported by the c-ares DNS backend */
  FETCHOPT(FETCHOPT_DNS_LOCAL_IP4, FETCHOPTTYPE_STRINGPOINT, 222),

  /* Set the local IPv6 address to use for outgoing DNS requests.
   * Only supported by the c-ares DNS backend */
  FETCHOPT(FETCHOPT_DNS_LOCAL_IP6, FETCHOPTTYPE_STRINGPOINT, 223),

  /* Set authentication options directly */
  FETCHOPT(FETCHOPT_LOGIN_OPTIONS, FETCHOPTTYPE_STRINGPOINT, 224),

  /* Enable/disable TLS NPN extension (http2 over ssl might fail without) */
  FETCHOPTDEPRECATED(FETCHOPT_SSL_ENABLE_NPN, FETCHOPTTYPE_LONG, 225,
                    7.86.0, "Has no function"),

  /* Enable/disable TLS ALPN extension (http2 over ssl might fail without) */
  FETCHOPT(FETCHOPT_SSL_ENABLE_ALPN, FETCHOPTTYPE_LONG, 226),

  /* Time to wait for a response to an HTTP request containing an
   * Expect: 100-continue header before sending the data anyway. */
  FETCHOPT(FETCHOPT_EXPECT_100_TIMEOUT_MS, FETCHOPTTYPE_LONG, 227),

  /* This points to a linked list of headers used for proxy requests only,
     struct fetch_slist kind */
  FETCHOPT(FETCHOPT_PROXYHEADER, FETCHOPTTYPE_SLISTPOINT, 228),

  /* Pass in a bitmask of "header options" */
  FETCHOPT(FETCHOPT_HEADEROPT, FETCHOPTTYPE_VALUES, 229),

  /* The public key in DER form used to validate the peer public key
     this option is used only if SSL_VERIFYPEER is true */
  FETCHOPT(FETCHOPT_PINNEDPUBLICKEY, FETCHOPTTYPE_STRINGPOINT, 230),

  /* Path to Unix domain socket */
  FETCHOPT(FETCHOPT_UNIX_SOCKET_PATH, FETCHOPTTYPE_STRINGPOINT, 231),

  /* Set if we should verify the certificate status. */
  FETCHOPT(FETCHOPT_SSL_VERIFYSTATUS, FETCHOPTTYPE_LONG, 232),

  /* Set if we should enable TLS false start. */
  FETCHOPT(FETCHOPT_SSL_FALSESTART, FETCHOPTTYPE_LONG, 233),

  /* Do not squash dot-dot sequences */
  FETCHOPT(FETCHOPT_PATH_AS_IS, FETCHOPTTYPE_LONG, 234),

  /* Proxy Service Name */
  FETCHOPT(FETCHOPT_PROXY_SERVICE_NAME, FETCHOPTTYPE_STRINGPOINT, 235),

  /* Service Name */
  FETCHOPT(FETCHOPT_SERVICE_NAME, FETCHOPTTYPE_STRINGPOINT, 236),

  /* Wait/do not wait for pipe/mutex to clarify */
  FETCHOPT(FETCHOPT_PIPEWAIT, FETCHOPTTYPE_LONG, 237),

  /* Set the protocol used when fetch is given a URL without a protocol */
  FETCHOPT(FETCHOPT_DEFAULT_PROTOCOL, FETCHOPTTYPE_STRINGPOINT, 238),

  /* Set stream weight, 1 - 256 (default is 16) */
  FETCHOPT(FETCHOPT_STREAM_WEIGHT, FETCHOPTTYPE_LONG, 239),

  /* Set stream dependency on another fetch handle */
  FETCHOPT(FETCHOPT_STREAM_DEPENDS, FETCHOPTTYPE_OBJECTPOINT, 240),

  /* Set E-xclusive stream dependency on another fetch handle */
  FETCHOPT(FETCHOPT_STREAM_DEPENDS_E, FETCHOPTTYPE_OBJECTPOINT, 241),

  /* Do not send any tftp option requests to the server */
  FETCHOPT(FETCHOPT_TFTP_NO_OPTIONS, FETCHOPTTYPE_LONG, 242),

  /* Linked-list of host:port:connect-to-host:connect-to-port,
     overrides the URL's host:port (only for the network layer) */
  FETCHOPT(FETCHOPT_CONNECT_TO, FETCHOPTTYPE_SLISTPOINT, 243),

  /* Set TCP Fast Open */
  FETCHOPT(FETCHOPT_TCP_FASTOPEN, FETCHOPTTYPE_LONG, 244),

  /* Continue to send data if the server responds early with an
   * HTTP status code >= 300 */
  FETCHOPT(FETCHOPT_KEEP_SENDING_ON_ERROR, FETCHOPTTYPE_LONG, 245),

  /* The CApath or CAfile used to validate the proxy certificate
     this option is used only if PROXY_SSL_VERIFYPEER is true */
  FETCHOPT(FETCHOPT_PROXY_CAINFO, FETCHOPTTYPE_STRINGPOINT, 246),

  /* The CApath directory used to validate the proxy certificate
     this option is used only if PROXY_SSL_VERIFYPEER is true */
  FETCHOPT(FETCHOPT_PROXY_CAPATH, FETCHOPTTYPE_STRINGPOINT, 247),

  /* Set if we should verify the proxy in ssl handshake,
     set 1 to verify. */
  FETCHOPT(FETCHOPT_PROXY_SSL_VERIFYPEER, FETCHOPTTYPE_LONG, 248),

  /* Set if we should verify the Common name from the proxy certificate in ssl
   * handshake, set 1 to check existence, 2 to ensure that it matches
   * the provided hostname. */
  FETCHOPT(FETCHOPT_PROXY_SSL_VERIFYHOST, FETCHOPTTYPE_LONG, 249),

  /* What version to specifically try to use for proxy.
     See FETCH_SSLVERSION defines below. */
  FETCHOPT(FETCHOPT_PROXY_SSLVERSION, FETCHOPTTYPE_VALUES, 250),

  /* Set a username for authenticated TLS for proxy */
  FETCHOPT(FETCHOPT_PROXY_TLSAUTH_USERNAME, FETCHOPTTYPE_STRINGPOINT, 251),

  /* Set a password for authenticated TLS for proxy */
  FETCHOPT(FETCHOPT_PROXY_TLSAUTH_PASSWORD, FETCHOPTTYPE_STRINGPOINT, 252),

  /* Set authentication type for authenticated TLS for proxy */
  FETCHOPT(FETCHOPT_PROXY_TLSAUTH_TYPE, FETCHOPTTYPE_STRINGPOINT, 253),

  /* name of the file keeping your private SSL-certificate for proxy */
  FETCHOPT(FETCHOPT_PROXY_SSLCERT, FETCHOPTTYPE_STRINGPOINT, 254),

  /* type of the file keeping your SSL-certificate ("DER", "PEM", "ENG") for
     proxy */
  FETCHOPT(FETCHOPT_PROXY_SSLCERTTYPE, FETCHOPTTYPE_STRINGPOINT, 255),

  /* name of the file keeping your private SSL-key for proxy */
  FETCHOPT(FETCHOPT_PROXY_SSLKEY, FETCHOPTTYPE_STRINGPOINT, 256),

  /* type of the file keeping your private SSL-key ("DER", "PEM", "ENG") for
     proxy */
  FETCHOPT(FETCHOPT_PROXY_SSLKEYTYPE, FETCHOPTTYPE_STRINGPOINT, 257),

  /* password for the SSL private key for proxy */
  FETCHOPT(FETCHOPT_PROXY_KEYPASSWD, FETCHOPTTYPE_STRINGPOINT, 258),

  /* Specify which TLS 1.2 (1.1, 1.0) ciphers to use for proxy */
  FETCHOPT(FETCHOPT_PROXY_SSL_CIPHER_LIST, FETCHOPTTYPE_STRINGPOINT, 259),

  /* CRL file for proxy */
  FETCHOPT(FETCHOPT_PROXY_CRLFILE, FETCHOPTTYPE_STRINGPOINT, 260),

  /* Enable/disable specific SSL features with a bitmask for proxy, see
     FETCHSSLOPT_* */
  FETCHOPT(FETCHOPT_PROXY_SSL_OPTIONS, FETCHOPTTYPE_LONG, 261),

  /* Name of pre proxy to use. */
  FETCHOPT(FETCHOPT_PRE_PROXY, FETCHOPTTYPE_STRINGPOINT, 262),

  /* The public key in DER form used to validate the proxy public key
     this option is used only if PROXY_SSL_VERIFYPEER is true */
  FETCHOPT(FETCHOPT_PROXY_PINNEDPUBLICKEY, FETCHOPTTYPE_STRINGPOINT, 263),

  /* Path to an abstract Unix domain socket */
  FETCHOPT(FETCHOPT_ABSTRACT_UNIX_SOCKET, FETCHOPTTYPE_STRINGPOINT, 264),

  /* Suppress proxy CONNECT response headers from user callbacks */
  FETCHOPT(FETCHOPT_SUPPRESS_CONNECT_HEADERS, FETCHOPTTYPE_LONG, 265),

  /* The request target, instead of extracted from the URL */
  FETCHOPT(FETCHOPT_REQUEST_TARGET, FETCHOPTTYPE_STRINGPOINT, 266),

  /* bitmask of allowed auth methods for connections to SOCKS5 proxies */
  FETCHOPT(FETCHOPT_SOCKS5_AUTH, FETCHOPTTYPE_LONG, 267),

  /* Enable/disable SSH compression */
  FETCHOPT(FETCHOPT_SSH_COMPRESSION, FETCHOPTTYPE_LONG, 268),

  /* Post MIME data. */
  FETCHOPT(FETCHOPT_MIMEPOST, FETCHOPTTYPE_OBJECTPOINT, 269),

  /* Time to use with the FETCHOPT_TIMECONDITION. Specified in number of
     seconds since 1 Jan 1970. */
  FETCHOPT(FETCHOPT_TIMEVALUE_LARGE, FETCHOPTTYPE_OFF_T, 270),

  /* Head start in milliseconds to give happy eyeballs. */
  FETCHOPT(FETCHOPT_HAPPY_EYEBALLS_TIMEOUT_MS, FETCHOPTTYPE_LONG, 271),

  /* Function that will be called before a resolver request is made */
  FETCHOPT(FETCHOPT_RESOLVER_START_FUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 272),

  /* User data to pass to the resolver start callback. */
  FETCHOPT(FETCHOPT_RESOLVER_START_DATA, FETCHOPTTYPE_CBPOINT, 273),

  /* send HAProxy PROXY protocol header? */
  FETCHOPT(FETCHOPT_HAPROXYPROTOCOL, FETCHOPTTYPE_LONG, 274),

  /* shuffle addresses before use when DNS returns multiple */
  FETCHOPT(FETCHOPT_DNS_SHUFFLE_ADDRESSES, FETCHOPTTYPE_LONG, 275),

  /* Specify which TLS 1.3 ciphers suites to use */
  FETCHOPT(FETCHOPT_TLS13_CIPHERS, FETCHOPTTYPE_STRINGPOINT, 276),
  FETCHOPT(FETCHOPT_PROXY_TLS13_CIPHERS, FETCHOPTTYPE_STRINGPOINT, 277),

  /* Disallow specifying username/login in URL. */
  FETCHOPT(FETCHOPT_DISALLOW_USERNAME_IN_URL, FETCHOPTTYPE_LONG, 278),

  /* DNS-over-HTTPS URL */
  FETCHOPT(FETCHOPT_DOH_URL, FETCHOPTTYPE_STRINGPOINT, 279),

  /* Preferred buffer size to use for uploads */
  FETCHOPT(FETCHOPT_UPLOAD_BUFFERSIZE, FETCHOPTTYPE_LONG, 280),

  /* Time in ms between connection upkeep calls for long-lived connections. */
  FETCHOPT(FETCHOPT_UPKEEP_INTERVAL_MS, FETCHOPTTYPE_LONG, 281),

  /* Specify URL using FETCH URL API. */
  FETCHOPT(FETCHOPT_FETCHU, FETCHOPTTYPE_OBJECTPOINT, 282),

  /* add trailing data just after no more data is available */
  FETCHOPT(FETCHOPT_TRAILERFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 283),

  /* pointer to be passed to HTTP_TRAILER_FUNCTION */
  FETCHOPT(FETCHOPT_TRAILERDATA, FETCHOPTTYPE_CBPOINT, 284),

  /* set this to 1L to allow HTTP/0.9 responses or 0L to disallow */
  FETCHOPT(FETCHOPT_HTTP09_ALLOWED, FETCHOPTTYPE_LONG, 285),

  /* alt-svc control bitmask */
  FETCHOPT(FETCHOPT_ALTSVC_CTRL, FETCHOPTTYPE_LONG, 286),

  /* alt-svc cache filename to possibly read from/write to */
  FETCHOPT(FETCHOPT_ALTSVC, FETCHOPTTYPE_STRINGPOINT, 287),

  /* maximum age (idle time) of a connection to consider it for reuse
   * (in seconds) */
  FETCHOPT(FETCHOPT_MAXAGE_CONN, FETCHOPTTYPE_LONG, 288),

  /* SASL authorization identity */
  FETCHOPT(FETCHOPT_SASL_AUTHZID, FETCHOPTTYPE_STRINGPOINT, 289),

  /* allow RCPT TO command to fail for some recipients */
  FETCHOPT(FETCHOPT_MAIL_RCPT_ALLOWFAILS, FETCHOPTTYPE_LONG, 290),

  /* the private SSL-certificate as a "blob" */
  FETCHOPT(FETCHOPT_SSLCERT_BLOB, FETCHOPTTYPE_BLOB, 291),
  FETCHOPT(FETCHOPT_SSLKEY_BLOB, FETCHOPTTYPE_BLOB, 292),
  FETCHOPT(FETCHOPT_PROXY_SSLCERT_BLOB, FETCHOPTTYPE_BLOB, 293),
  FETCHOPT(FETCHOPT_PROXY_SSLKEY_BLOB, FETCHOPTTYPE_BLOB, 294),
  FETCHOPT(FETCHOPT_ISSUERCERT_BLOB, FETCHOPTTYPE_BLOB, 295),

  /* Issuer certificate for proxy */
  FETCHOPT(FETCHOPT_PROXY_ISSUERCERT, FETCHOPTTYPE_STRINGPOINT, 296),
  FETCHOPT(FETCHOPT_PROXY_ISSUERCERT_BLOB, FETCHOPTTYPE_BLOB, 297),

  /* the EC curves requested by the TLS client (RFC 8422, 5.1);
   * OpenSSL support via 'set_groups'/'set_curves':
   * https://docs.openssl.org/master/man3/SSL_CTX_set1_curves/
   */
  FETCHOPT(FETCHOPT_SSL_EC_CURVES, FETCHOPTTYPE_STRINGPOINT, 298),

  /* HSTS bitmask */
  FETCHOPT(FETCHOPT_HSTS_CTRL, FETCHOPTTYPE_LONG, 299),
  /* HSTS filename */
  FETCHOPT(FETCHOPT_HSTS, FETCHOPTTYPE_STRINGPOINT, 300),

  /* HSTS read callback */
  FETCHOPT(FETCHOPT_HSTSREADFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 301),
  FETCHOPT(FETCHOPT_HSTSREADDATA, FETCHOPTTYPE_CBPOINT, 302),

  /* HSTS write callback */
  FETCHOPT(FETCHOPT_HSTSWRITEFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 303),
  FETCHOPT(FETCHOPT_HSTSWRITEDATA, FETCHOPTTYPE_CBPOINT, 304),

  /* Parameters for V4 signature */
  FETCHOPT(FETCHOPT_AWS_SIGV4, FETCHOPTTYPE_STRINGPOINT, 305),

  /* Same as FETCHOPT_SSL_VERIFYPEER but for DoH (DNS-over-HTTPS) servers. */
  FETCHOPT(FETCHOPT_DOH_SSL_VERIFYPEER, FETCHOPTTYPE_LONG, 306),

  /* Same as FETCHOPT_SSL_VERIFYHOST but for DoH (DNS-over-HTTPS) servers. */
  FETCHOPT(FETCHOPT_DOH_SSL_VERIFYHOST, FETCHOPTTYPE_LONG, 307),

  /* Same as FETCHOPT_SSL_VERIFYSTATUS but for DoH (DNS-over-HTTPS) servers. */
  FETCHOPT(FETCHOPT_DOH_SSL_VERIFYSTATUS, FETCHOPTTYPE_LONG, 308),

  /* The CA certificates as "blob" used to validate the peer certificate
     this option is used only if SSL_VERIFYPEER is true */
  FETCHOPT(FETCHOPT_CAINFO_BLOB, FETCHOPTTYPE_BLOB, 309),

  /* The CA certificates as "blob" used to validate the proxy certificate
     this option is used only if PROXY_SSL_VERIFYPEER is true */
  FETCHOPT(FETCHOPT_PROXY_CAINFO_BLOB, FETCHOPTTYPE_BLOB, 310),

  /* used by scp/sftp to verify the host's public key */
  FETCHOPT(FETCHOPT_SSH_HOST_PUBLIC_KEY_SHA256, FETCHOPTTYPE_STRINGPOINT, 311),

  /* Function that will be called immediately before the initial request
     is made on a connection (after any protocol negotiation step).  */
  FETCHOPT(FETCHOPT_PREREQFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 312),

  /* Data passed to the FETCHOPT_PREREQFUNCTION callback */
  FETCHOPT(FETCHOPT_PREREQDATA, FETCHOPTTYPE_CBPOINT, 313),

  /* maximum age (since creation) of a connection to consider it for reuse
   * (in seconds) */
  FETCHOPT(FETCHOPT_MAXLIFETIME_CONN, FETCHOPTTYPE_LONG, 314),

  /* Set MIME option flags. */
  FETCHOPT(FETCHOPT_MIME_OPTIONS, FETCHOPTTYPE_LONG, 315),

  /* set the SSH host key callback, must point to a fetch_sshkeycallback
     function */
  FETCHOPT(FETCHOPT_SSH_HOSTKEYFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 316),

  /* set the SSH host key callback custom pointer */
  FETCHOPT(FETCHOPT_SSH_HOSTKEYDATA, FETCHOPTTYPE_CBPOINT, 317),

  /* specify which protocols that are allowed to be used for the transfer,
     which thus helps the app which takes URLs from users or other external
     inputs and want to restrict what protocol(s) to deal with. Defaults to
     all built-in protocols. */
  FETCHOPT(FETCHOPT_PROTOCOLS_STR, FETCHOPTTYPE_STRINGPOINT, 318),

  /* specify which protocols that libfetch is allowed to follow directs to */
  FETCHOPT(FETCHOPT_REDIR_PROTOCOLS_STR, FETCHOPTTYPE_STRINGPOINT, 319),

  /* WebSockets options */
  FETCHOPT(FETCHOPT_WS_OPTIONS, FETCHOPTTYPE_LONG, 320),

  /* CA cache timeout */
  FETCHOPT(FETCHOPT_CA_CACHE_TIMEOUT, FETCHOPTTYPE_LONG, 321),

  /* Can leak things, gonna exit() soon */
  FETCHOPT(FETCHOPT_QUICK_EXIT, FETCHOPTTYPE_LONG, 322),

  /* set a specific client IP for HAProxy PROXY protocol header? */
  FETCHOPT(FETCHOPT_HAPROXY_CLIENT_IP, FETCHOPTTYPE_STRINGPOINT, 323),

  /* millisecond version */
  FETCHOPT(FETCHOPT_SERVER_RESPONSE_TIMEOUT_MS, FETCHOPTTYPE_LONG, 324),

  /* set ECH configuration */
  FETCHOPT(FETCHOPT_ECH, FETCHOPTTYPE_STRINGPOINT, 325),

  /* maximum number of keepalive probes (Linux, *BSD, macOS, etc.) */
  FETCHOPT(FETCHOPT_TCP_KEEPCNT, FETCHOPTTYPE_LONG, 326),

  FETCHOPT_LASTENTRY /* the last unused */
} FETCHoption;

#ifndef FETCH_NO_OLDIES /* define this to test if your app builds with all
                          the obsolete stuff removed! */

/* Backwards compatibility with older names */
/* These are scheduled to disappear by 2011 */

/* This was added in version 7.19.1 */
#define FETCHOPT_POST301 FETCHOPT_POSTREDIR

/* These are scheduled to disappear by 2009 */

/* The following were added in 7.17.0 */
#define FETCHOPT_SSLKEYPASSWD FETCHOPT_KEYPASSWD
#define FETCHOPT_FTPAPPEND FETCHOPT_APPEND
#define FETCHOPT_FTPLISTONLY FETCHOPT_DIRLISTONLY
#define FETCHOPT_FTP_SSL FETCHOPT_USE_SSL

/* The following were added earlier */

#define FETCHOPT_SSLCERTPASSWD FETCHOPT_KEYPASSWD
#define FETCHOPT_KRB4LEVEL FETCHOPT_KRBLEVEL

/* */
#define FETCHOPT_FTP_RESPONSE_TIMEOUT FETCHOPT_SERVER_RESPONSE_TIMEOUT

/* Added in 8.2.0 */
#define FETCHOPT_MAIL_RCPT_ALLLOWFAILS FETCHOPT_MAIL_RCPT_ALLOWFAILS

#else
/* This is set if FETCH_NO_OLDIES is defined at compile-time */
#undef FETCHOPT_DNS_USE_GLOBAL_CACHE /* soon obsolete */
#endif


  /* Below here follows defines for the FETCHOPT_IPRESOLVE option. If a host
     name resolves addresses using more than one IP protocol version, this
     option might be handy to force libfetch to use a specific IP version. */
#define FETCH_IPRESOLVE_WHATEVER 0 /* default, uses addresses to all IP
                                     versions that your system allows */
#define FETCH_IPRESOLVE_V4       1 /* uses only IPv4 addresses/connections */
#define FETCH_IPRESOLVE_V6       2 /* uses only IPv6 addresses/connections */

  /* Convenient "aliases" */
#define FETCHOPT_RTSPHEADER FETCHOPT_HTTPHEADER

  /* These enums are for use with the FETCHOPT_HTTP_VERSION option. */
enum {
  FETCH_HTTP_VERSION_NONE, /* setting this means we do not care, and that we
                             would like the library to choose the best
                             possible for us! */
  FETCH_HTTP_VERSION_1_0,  /* please use HTTP 1.0 in the request */
  FETCH_HTTP_VERSION_1_1,  /* please use HTTP 1.1 in the request */
  FETCH_HTTP_VERSION_2_0,  /* please use HTTP 2 in the request */
  FETCH_HTTP_VERSION_2TLS, /* use version 2 for HTTPS, version 1.1 for HTTP */
  FETCH_HTTP_VERSION_2_PRIOR_KNOWLEDGE,  /* please use HTTP 2 without HTTP/1.1
                                           Upgrade */
  FETCH_HTTP_VERSION_3 = 30, /* Use HTTP/3, fallback to HTTP/2 or HTTP/1 if
                               needed. For HTTPS only. For HTTP, this option
                               makes libfetch return error. */
  FETCH_HTTP_VERSION_3ONLY = 31, /* Use HTTP/3 without fallback. For HTTPS
                                   only. For HTTP, this makes libfetch
                                   return error. */

  FETCH_HTTP_VERSION_LAST /* *ILLEGAL* http version */
};

/* Convenience definition simple because the name of the version is HTTP/2 and
   not 2.0. The 2_0 version of the enum name was set while the version was
   still planned to be 2.0 and we stick to it for compatibility. */
#define FETCH_HTTP_VERSION_2 FETCH_HTTP_VERSION_2_0

/*
 * Public API enums for RTSP requests
 */
enum {
    FETCH_RTSPREQ_NONE, /* first in list */
    FETCH_RTSPREQ_OPTIONS,
    FETCH_RTSPREQ_DESCRIBE,
    FETCH_RTSPREQ_ANNOUNCE,
    FETCH_RTSPREQ_SETUP,
    FETCH_RTSPREQ_PLAY,
    FETCH_RTSPREQ_PAUSE,
    FETCH_RTSPREQ_TEARDOWN,
    FETCH_RTSPREQ_GET_PARAMETER,
    FETCH_RTSPREQ_SET_PARAMETER,
    FETCH_RTSPREQ_RECORD,
    FETCH_RTSPREQ_RECEIVE,
    FETCH_RTSPREQ_LAST /* last in list */
};

  /* These enums are for use with the FETCHOPT_NETRC option. */
enum FETCH_NETRC_OPTION {
  FETCH_NETRC_IGNORED,     /* The .netrc will never be read.
                           * This is the default. */
  FETCH_NETRC_OPTIONAL,    /* A user:password in the URL will be preferred
                           * to one in the .netrc. */
  FETCH_NETRC_REQUIRED,    /* A user:password in the URL will be ignored.
                           * Unless one is set programmatically, the .netrc
                           * will be queried. */
  FETCH_NETRC_LAST
};

#define FETCH_SSLVERSION_DEFAULT 0
#define FETCH_SSLVERSION_TLSv1   1 /* TLS 1.x */
#define FETCH_SSLVERSION_SSLv2   2
#define FETCH_SSLVERSION_SSLv3   3
#define FETCH_SSLVERSION_TLSv1_0 4
#define FETCH_SSLVERSION_TLSv1_1 5
#define FETCH_SSLVERSION_TLSv1_2 6
#define FETCH_SSLVERSION_TLSv1_3 7

#define FETCH_SSLVERSION_LAST 8 /* never use, keep last */

#define FETCH_SSLVERSION_MAX_NONE 0
#define FETCH_SSLVERSION_MAX_DEFAULT (FETCH_SSLVERSION_TLSv1   << 16)
#define FETCH_SSLVERSION_MAX_TLSv1_0 (FETCH_SSLVERSION_TLSv1_0 << 16)
#define FETCH_SSLVERSION_MAX_TLSv1_1 (FETCH_SSLVERSION_TLSv1_1 << 16)
#define FETCH_SSLVERSION_MAX_TLSv1_2 (FETCH_SSLVERSION_TLSv1_2 << 16)
#define FETCH_SSLVERSION_MAX_TLSv1_3 (FETCH_SSLVERSION_TLSv1_3 << 16)

  /* never use, keep last */
#define FETCH_SSLVERSION_MAX_LAST    (FETCH_SSLVERSION_LAST    << 16)

enum FETCH_TLSAUTH {
  FETCH_TLSAUTH_NONE,
  FETCH_TLSAUTH_SRP,
  FETCH_TLSAUTH_LAST /* never use, keep last */
};

/* symbols to use with FETCHOPT_POSTREDIR.
   FETCH_REDIR_POST_301, FETCH_REDIR_POST_302 and FETCH_REDIR_POST_303
   can be bitwise ORed so that FETCH_REDIR_POST_301 | FETCH_REDIR_POST_302
   | FETCH_REDIR_POST_303 == FETCH_REDIR_POST_ALL */

#define FETCH_REDIR_GET_ALL  0
#define FETCH_REDIR_POST_301 1
#define FETCH_REDIR_POST_302 2
#define FETCH_REDIR_POST_303 4
#define FETCH_REDIR_POST_ALL \
    (FETCH_REDIR_POST_301|FETCH_REDIR_POST_302|FETCH_REDIR_POST_303)

typedef enum {
  FETCH_TIMECOND_NONE,

  FETCH_TIMECOND_IFMODSINCE,
  FETCH_TIMECOND_IFUNMODSINCE,
  FETCH_TIMECOND_LASTMOD,

  FETCH_TIMECOND_LAST
} fetch_TimeCond;

/* Special size_t value signaling a null-terminated string. */
#define FETCH_ZERO_TERMINATED ((size_t) -1)

/* fetch_strequal() and fetch_strnequal() are subject for removal in a future
   release */
FETCH_EXTERN int fetch_strequal(const char *s1, const char *s2);
FETCH_EXTERN int fetch_strnequal(const char *s1, const char *s2, size_t n);

/* Mime/form handling support. */
typedef struct fetch_mime      fetch_mime;      /* Mime context. */
typedef struct fetch_mimepart  fetch_mimepart;  /* Mime part context. */

/* FETCHMIMEOPT_ defines are for the FETCHOPT_MIME_OPTIONS option. */
#define FETCHMIMEOPT_FORMESCAPE  (1<<0) /* Use backslash-escaping for forms. */

/*
 * NAME fetch_mime_init()
 *
 * DESCRIPTION
 *
 * Create a mime context and return its handle. The easy parameter is the
 * target handle.
 */
FETCH_EXTERN fetch_mime *fetch_mime_init(FETCH *easy);

/*
 * NAME fetch_mime_free()
 *
 * DESCRIPTION
 *
 * release a mime handle and its substructures.
 */
FETCH_EXTERN void fetch_mime_free(fetch_mime *mime);

/*
 * NAME fetch_mime_addpart()
 *
 * DESCRIPTION
 *
 * Append a new empty part to the given mime context and return a handle to
 * the created part.
 */
FETCH_EXTERN fetch_mimepart *fetch_mime_addpart(fetch_mime *mime);

/*
 * NAME fetch_mime_name()
 *
 * DESCRIPTION
 *
 * Set mime/form part name.
 */
FETCH_EXTERN FETCHcode fetch_mime_name(fetch_mimepart *part, const char *name);

/*
 * NAME fetch_mime_filename()
 *
 * DESCRIPTION
 *
 * Set mime part remote filename.
 */
FETCH_EXTERN FETCHcode fetch_mime_filename(fetch_mimepart *part,
                                        const char *filename);

/*
 * NAME fetch_mime_type()
 *
 * DESCRIPTION
 *
 * Set mime part type.
 */
FETCH_EXTERN FETCHcode fetch_mime_type(fetch_mimepart *part, const char *mimetype);

/*
 * NAME fetch_mime_encoder()
 *
 * DESCRIPTION
 *
 * Set mime data transfer encoder.
 */
FETCH_EXTERN FETCHcode fetch_mime_encoder(fetch_mimepart *part,
                                       const char *encoding);

/*
 * NAME fetch_mime_data()
 *
 * DESCRIPTION
 *
 * Set mime part data source from memory data,
 */
FETCH_EXTERN FETCHcode fetch_mime_data(fetch_mimepart *part,
                                    const char *data, size_t datasize);

/*
 * NAME fetch_mime_filedata()
 *
 * DESCRIPTION
 *
 * Set mime part data source from named file.
 */
FETCH_EXTERN FETCHcode fetch_mime_filedata(fetch_mimepart *part,
                                        const char *filename);

/*
 * NAME fetch_mime_data_cb()
 *
 * DESCRIPTION
 *
 * Set mime part data source from callback function.
 */
FETCH_EXTERN FETCHcode fetch_mime_data_cb(fetch_mimepart *part,
                                       fetch_off_t datasize,
                                       fetch_read_callback readfunc,
                                       fetch_seek_callback seekfunc,
                                       fetch_free_callback freefunc,
                                       void *arg);

/*
 * NAME fetch_mime_subparts()
 *
 * DESCRIPTION
 *
 * Set mime part data source from subparts.
 */
FETCH_EXTERN FETCHcode fetch_mime_subparts(fetch_mimepart *part,
                                        fetch_mime *subparts);
/*
 * NAME fetch_mime_headers()
 *
 * DESCRIPTION
 *
 * Set mime part headers.
 */
FETCH_EXTERN FETCHcode fetch_mime_headers(fetch_mimepart *part,
                                       struct fetch_slist *headers,
                                       int take_ownership);

typedef enum {
  /********* the first one is unused ************/
  FETCHFORM_NOTHING         FETCH_DEPRECATED(7.56.0, ""),
  FETCHFORM_COPYNAME        FETCH_DEPRECATED(7.56.0, "Use fetch_mime_name()"),
  FETCHFORM_PTRNAME         FETCH_DEPRECATED(7.56.0, "Use fetch_mime_name()"),
  FETCHFORM_NAMELENGTH      FETCH_DEPRECATED(7.56.0, ""),
  FETCHFORM_COPYCONTENTS    FETCH_DEPRECATED(7.56.0, "Use fetch_mime_data()"),
  FETCHFORM_PTRCONTENTS     FETCH_DEPRECATED(7.56.0, "Use fetch_mime_data()"),
  FETCHFORM_CONTENTSLENGTH  FETCH_DEPRECATED(7.56.0, "Use fetch_mime_data()"),
  FETCHFORM_FILECONTENT     FETCH_DEPRECATED(7.56.0, "Use fetch_mime_data_cb()"),
  FETCHFORM_ARRAY           FETCH_DEPRECATED(7.56.0, ""),
  FETCHFORM_OBSOLETE,
  FETCHFORM_FILE            FETCH_DEPRECATED(7.56.0, "Use fetch_mime_filedata()"),

  FETCHFORM_BUFFER          FETCH_DEPRECATED(7.56.0, "Use fetch_mime_filename()"),
  FETCHFORM_BUFFERPTR       FETCH_DEPRECATED(7.56.0, "Use fetch_mime_data()"),
  FETCHFORM_BUFFERLENGTH    FETCH_DEPRECATED(7.56.0, "Use fetch_mime_data()"),

  FETCHFORM_CONTENTTYPE     FETCH_DEPRECATED(7.56.0, "Use fetch_mime_type()"),
  FETCHFORM_CONTENTHEADER   FETCH_DEPRECATED(7.56.0, "Use fetch_mime_headers()"),
  FETCHFORM_FILENAME        FETCH_DEPRECATED(7.56.0, "Use fetch_mime_filename()"),
  FETCHFORM_END,
  FETCHFORM_OBSOLETE2,

  FETCHFORM_STREAM          FETCH_DEPRECATED(7.56.0, "Use fetch_mime_data_cb()"),
  FETCHFORM_CONTENTLEN  /* added in 7.46.0, provide a fetch_off_t length */
                           FETCH_DEPRECATED(7.56.0, "Use fetch_mime_data()"),

  FETCHFORM_LASTENTRY /* the last unused */
} FETCHformoption;

/* structure to be used as parameter for FETCHFORM_ARRAY */
struct fetch_forms {
  FETCHformoption option;
  const char     *value;
};

/* use this for multipart formpost building */
/* Returns code for fetch_formadd()
 *
 * Returns:
 * FETCH_FORMADD_OK             on success
 * FETCH_FORMADD_MEMORY         if the FormInfo allocation fails
 * FETCH_FORMADD_OPTION_TWICE   if one option is given twice for one Form
 * FETCH_FORMADD_NULL           if a null pointer was given for a char
 * FETCH_FORMADD_MEMORY         if the allocation of a FormInfo struct failed
 * FETCH_FORMADD_UNKNOWN_OPTION if an unknown option was used
 * FETCH_FORMADD_INCOMPLETE     if the some FormInfo is not complete (or error)
 * FETCH_FORMADD_MEMORY         if a fetch_httppost struct cannot be allocated
 * FETCH_FORMADD_MEMORY         if some allocation for string copying failed.
 * FETCH_FORMADD_ILLEGAL_ARRAY  if an illegal option is used in an array
 *
 ***************************************************************************/
typedef enum {
  FETCH_FORMADD_OK             FETCH_DEPRECATED(7.56.0, ""), /* 1st, no error */

  FETCH_FORMADD_MEMORY         FETCH_DEPRECATED(7.56.0, ""),
  FETCH_FORMADD_OPTION_TWICE   FETCH_DEPRECATED(7.56.0, ""),
  FETCH_FORMADD_NULL           FETCH_DEPRECATED(7.56.0, ""),
  FETCH_FORMADD_UNKNOWN_OPTION FETCH_DEPRECATED(7.56.0, ""),
  FETCH_FORMADD_INCOMPLETE     FETCH_DEPRECATED(7.56.0, ""),
  FETCH_FORMADD_ILLEGAL_ARRAY  FETCH_DEPRECATED(7.56.0, ""),
  /* libfetch was built with form api disabled */
  FETCH_FORMADD_DISABLED       FETCH_DEPRECATED(7.56.0, ""),

  FETCH_FORMADD_LAST /* last */
} FETCHFORMcode;

/*
 * NAME fetch_formadd()
 *
 * DESCRIPTION
 *
 * Pretty advanced function for building multi-part formposts. Each invoke
 * adds one part that together construct a full post. Then use
 * FETCHOPT_HTTPPOST to send it off to libfetch.
 */
FETCH_EXTERN FETCHFORMcode FETCH_DEPRECATED(7.56.0, "Use fetch_mime_init()")
fetch_formadd(struct fetch_httppost **httppost,
             struct fetch_httppost **last_post,
             ...);

/*
 * callback function for fetch_formget()
 * The void *arg pointer will be the one passed as second argument to
 *   fetch_formget().
 * The character buffer passed to it must not be freed.
 * Should return the buffer length passed to it as the argument "len" on
 *   success.
 */
typedef size_t (*fetch_formget_callback)(void *arg, const char *buf,
                                        size_t len);

/*
 * NAME fetch_formget()
 *
 * DESCRIPTION
 *
 * Serialize a fetch_httppost struct built with fetch_formadd().
 * Accepts a void pointer as second argument which will be passed to
 * the fetch_formget_callback function.
 * Returns 0 on success.
 */
FETCH_EXTERN int FETCH_DEPRECATED(7.56.0, "")
fetch_formget(struct fetch_httppost *form, void *arg,
             fetch_formget_callback append);
/*
 * NAME fetch_formfree()
 *
 * DESCRIPTION
 *
 * Free a multipart formpost previously built with fetch_formadd().
 */
FETCH_EXTERN void FETCH_DEPRECATED(7.56.0, "Use fetch_mime_free()")
fetch_formfree(struct fetch_httppost *form);

/*
 * NAME fetch_getenv()
 *
 * DESCRIPTION
 *
 * Returns a malloc()'ed string that MUST be fetch_free()ed after usage is
 * complete. DEPRECATED - see lib/README.fetchx
 */
FETCH_EXTERN char *fetch_getenv(const char *variable);

/*
 * NAME fetch_version()
 *
 * DESCRIPTION
 *
 * Returns a static ASCII string of the libfetch version.
 */
FETCH_EXTERN char *fetch_version(void);

/*
 * NAME fetch_easy_escape()
 *
 * DESCRIPTION
 *
 * Escapes URL strings (converts all letters consider illegal in URLs to their
 * %XX versions). This function returns a new allocated string or NULL if an
 * error occurred.
 */
FETCH_EXTERN char *fetch_easy_escape(FETCH *handle,
                                   const char *string,
                                   int length);

/* the previous version: */
FETCH_EXTERN char *fetch_escape(const char *string,
                              int length);


/*
 * NAME fetch_easy_unescape()
 *
 * DESCRIPTION
 *
 * Unescapes URL encoding in strings (converts all %XX codes to their 8bit
 * versions). This function returns a new allocated string or NULL if an error
 * occurred.
 * Conversion Note: On non-ASCII platforms the ASCII %XX codes are
 * converted into the host encoding.
 */
FETCH_EXTERN char *fetch_easy_unescape(FETCH *handle,
                                     const char *string,
                                     int length,
                                     int *outlength);

/* the previous version */
FETCH_EXTERN char *fetch_unescape(const char *string,
                                int length);

/*
 * NAME fetch_free()
 *
 * DESCRIPTION
 *
 * Provided for de-allocation in the same translation unit that did the
 * allocation. Added in libfetch 7.10
 */
FETCH_EXTERN void fetch_free(void *p);

/*
 * NAME fetch_global_init()
 *
 * DESCRIPTION
 *
 * fetch_global_init() should be invoked exactly once for each application that
 * uses libfetch and before any call of other libfetch functions.

 * This function is thread-safe if FETCH_VERSION_THREADSAFE is set in the
 * fetch_version_info_data.features flag (fetch by fetch_version_info()).

 */
FETCH_EXTERN FETCHcode fetch_global_init(long flags);

/*
 * NAME fetch_global_init_mem()
 *
 * DESCRIPTION
 *
 * fetch_global_init() or fetch_global_init_mem() should be invoked exactly once
 * for each application that uses libfetch. This function can be used to
 * initialize libfetch and set user defined memory management callback
 * functions. Users can implement memory management routines to check for
 * memory leaks, check for mis-use of the fetch library etc. User registered
 * callback routines will be invoked by this library instead of the system
 * memory management routines like malloc, free etc.
 */
FETCH_EXTERN FETCHcode fetch_global_init_mem(long flags,
                                          fetch_malloc_callback m,
                                          fetch_free_callback f,
                                          fetch_realloc_callback r,
                                          fetch_strdup_callback s,
                                          fetch_calloc_callback c);

/*
 * NAME fetch_global_cleanup()
 *
 * DESCRIPTION
 *
 * fetch_global_cleanup() should be invoked exactly once for each application
 * that uses libfetch
 */
FETCH_EXTERN void fetch_global_cleanup(void);

/*
 * NAME fetch_global_trace()
 *
 * DESCRIPTION
 *
 * fetch_global_trace() can be invoked at application start to
 * configure which components in fetch should participate in tracing.

 * This function is thread-safe if FETCH_VERSION_THREADSAFE is set in the
 * fetch_version_info_data.features flag (fetch by fetch_version_info()).

 */
FETCH_EXTERN FETCHcode fetch_global_trace(const char *config);

/* linked-list structure for the FETCHOPT_QUOTE option (and other) */
struct fetch_slist {
  char *data;
  struct fetch_slist *next;
};

/*
 * NAME fetch_global_sslset()
 *
 * DESCRIPTION
 *
 * When built with multiple SSL backends, fetch_global_sslset() allows to
 * choose one. This function can only be called once, and it must be called
 * *before* fetch_global_init().
 *
 * The backend can be identified by the id (e.g. FETCHSSLBACKEND_OPENSSL). The
 * backend can also be specified via the name parameter (passing -1 as id).
 * If both id and name are specified, the name will be ignored. If neither id
 * nor name are specified, the function will fail with
 * FETCHSSLSET_UNKNOWN_BACKEND and set the "avail" pointer to the
 * NULL-terminated list of available backends.
 *
 * Upon success, the function returns FETCHSSLSET_OK.
 *
 * If the specified SSL backend is not available, the function returns
 * FETCHSSLSET_UNKNOWN_BACKEND and sets the "avail" pointer to a NULL-terminated
 * list of available SSL backends.
 *
 * The SSL backend can be set only once. If it has already been set, a
 * subsequent attempt to change it will result in a FETCHSSLSET_TOO_LATE.
 */

struct fetch_ssl_backend {
  fetch_sslbackend id;
  const char *name;
};
typedef struct fetch_ssl_backend fetch_ssl_backend;

typedef enum {
  FETCHSSLSET_OK = 0,
  FETCHSSLSET_UNKNOWN_BACKEND,
  FETCHSSLSET_TOO_LATE,
  FETCHSSLSET_NO_BACKENDS /* libfetch was built without any SSL support */
} FETCHsslset;

FETCH_EXTERN FETCHsslset fetch_global_sslset(fetch_sslbackend id, const char *name,
                                          const fetch_ssl_backend ***avail);

/*
 * NAME fetch_slist_append()
 *
 * DESCRIPTION
 *
 * Appends a string to a linked list. If no list exists, it will be created
 * first. Returns the new list, after appending.
 */
FETCH_EXTERN struct fetch_slist *fetch_slist_append(struct fetch_slist *list,
                                                 const char *data);

/*
 * NAME fetch_slist_free_all()
 *
 * DESCRIPTION
 *
 * free a previously built fetch_slist.
 */
FETCH_EXTERN void fetch_slist_free_all(struct fetch_slist *list);

/*
 * NAME fetch_getdate()
 *
 * DESCRIPTION
 *
 * Returns the time, in seconds since 1 Jan 1970 of the time string given in
 * the first argument. The time argument in the second parameter is unused
 * and should be set to NULL.
 */
FETCH_EXTERN time_t fetch_getdate(const char *p, const time_t *unused);

/* info about the certificate chain, for SSL backends that support it. Asked
   for with FETCHOPT_CERTINFO / FETCHINFO_CERTINFO */
struct fetch_certinfo {
  int num_of_certs;             /* number of certificates with information */
  struct fetch_slist **certinfo; /* for each index in this array, there is a
                                   linked list with textual information for a
                                   certificate in the format "name:content".
                                   eg "Subject:foo", "Issuer:bar", etc. */
};

/* Information about the SSL library used and the respective internal SSL
   handle, which can be used to obtain further information regarding the
   connection. Asked for with FETCHINFO_TLS_SSL_PTR or FETCHINFO_TLS_SESSION. */
struct fetch_tlssessioninfo {
  fetch_sslbackend backend;
  void *internals;
};

#define FETCHINFO_STRING   0x100000
#define FETCHINFO_LONG     0x200000
#define FETCHINFO_DOUBLE   0x300000
#define FETCHINFO_SLIST    0x400000
#define FETCHINFO_PTR      0x400000 /* same as SLIST */
#define FETCHINFO_SOCKET   0x500000
#define FETCHINFO_OFF_T    0x600000
#define FETCHINFO_MASK     0x0fffff
#define FETCHINFO_TYPEMASK 0xf00000

typedef enum {
  FETCHINFO_NONE, /* first, never use this */
  FETCHINFO_EFFECTIVE_URL    = FETCHINFO_STRING + 1,
  FETCHINFO_RESPONSE_CODE    = FETCHINFO_LONG   + 2,
  FETCHINFO_TOTAL_TIME       = FETCHINFO_DOUBLE + 3,
  FETCHINFO_NAMELOOKUP_TIME  = FETCHINFO_DOUBLE + 4,
  FETCHINFO_CONNECT_TIME     = FETCHINFO_DOUBLE + 5,
  FETCHINFO_PRETRANSFER_TIME = FETCHINFO_DOUBLE + 6,
  FETCHINFO_SIZE_UPLOAD FETCH_DEPRECATED(7.55.0, "Use FETCHINFO_SIZE_UPLOAD_T")
                            = FETCHINFO_DOUBLE + 7,
  FETCHINFO_SIZE_UPLOAD_T    = FETCHINFO_OFF_T  + 7,
  FETCHINFO_SIZE_DOWNLOAD
                       FETCH_DEPRECATED(7.55.0, "Use FETCHINFO_SIZE_DOWNLOAD_T")
                            = FETCHINFO_DOUBLE + 8,
  FETCHINFO_SIZE_DOWNLOAD_T  = FETCHINFO_OFF_T  + 8,
  FETCHINFO_SPEED_DOWNLOAD
                       FETCH_DEPRECATED(7.55.0, "Use FETCHINFO_SPEED_DOWNLOAD_T")
                            = FETCHINFO_DOUBLE + 9,
  FETCHINFO_SPEED_DOWNLOAD_T = FETCHINFO_OFF_T  + 9,
  FETCHINFO_SPEED_UPLOAD
                       FETCH_DEPRECATED(7.55.0, "Use FETCHINFO_SPEED_UPLOAD_T")
                            = FETCHINFO_DOUBLE + 10,
  FETCHINFO_SPEED_UPLOAD_T   = FETCHINFO_OFF_T  + 10,
  FETCHINFO_HEADER_SIZE      = FETCHINFO_LONG   + 11,
  FETCHINFO_REQUEST_SIZE     = FETCHINFO_LONG   + 12,
  FETCHINFO_SSL_VERIFYRESULT = FETCHINFO_LONG   + 13,
  FETCHINFO_FILETIME         = FETCHINFO_LONG   + 14,
  FETCHINFO_FILETIME_T       = FETCHINFO_OFF_T  + 14,
  FETCHINFO_CONTENT_LENGTH_DOWNLOAD
                       FETCH_DEPRECATED(7.55.0,
                                      "Use FETCHINFO_CONTENT_LENGTH_DOWNLOAD_T")
                            = FETCHINFO_DOUBLE + 15,
  FETCHINFO_CONTENT_LENGTH_DOWNLOAD_T = FETCHINFO_OFF_T  + 15,
  FETCHINFO_CONTENT_LENGTH_UPLOAD
                       FETCH_DEPRECATED(7.55.0,
                                       "Use FETCHINFO_CONTENT_LENGTH_UPLOAD_T")
                            = FETCHINFO_DOUBLE + 16,
  FETCHINFO_CONTENT_LENGTH_UPLOAD_T   = FETCHINFO_OFF_T  + 16,
  FETCHINFO_STARTTRANSFER_TIME = FETCHINFO_DOUBLE + 17,
  FETCHINFO_CONTENT_TYPE     = FETCHINFO_STRING + 18,
  FETCHINFO_REDIRECT_TIME    = FETCHINFO_DOUBLE + 19,
  FETCHINFO_REDIRECT_COUNT   = FETCHINFO_LONG   + 20,
  FETCHINFO_PRIVATE          = FETCHINFO_STRING + 21,
  FETCHINFO_HTTP_CONNECTCODE = FETCHINFO_LONG   + 22,
  FETCHINFO_HTTPAUTH_AVAIL   = FETCHINFO_LONG   + 23,
  FETCHINFO_PROXYAUTH_AVAIL  = FETCHINFO_LONG   + 24,
  FETCHINFO_OS_ERRNO         = FETCHINFO_LONG   + 25,
  FETCHINFO_NUM_CONNECTS     = FETCHINFO_LONG   + 26,
  FETCHINFO_SSL_ENGINES      = FETCHINFO_SLIST  + 27,
  FETCHINFO_COOKIELIST       = FETCHINFO_SLIST  + 28,
  FETCHINFO_LASTSOCKET  FETCH_DEPRECATED(7.45.0, "Use FETCHINFO_ACTIVESOCKET")
                            = FETCHINFO_LONG   + 29,
  FETCHINFO_FTP_ENTRY_PATH   = FETCHINFO_STRING + 30,
  FETCHINFO_REDIRECT_URL     = FETCHINFO_STRING + 31,
  FETCHINFO_PRIMARY_IP       = FETCHINFO_STRING + 32,
  FETCHINFO_APPCONNECT_TIME  = FETCHINFO_DOUBLE + 33,
  FETCHINFO_CERTINFO         = FETCHINFO_PTR    + 34,
  FETCHINFO_CONDITION_UNMET  = FETCHINFO_LONG   + 35,
  FETCHINFO_RTSP_SESSION_ID  = FETCHINFO_STRING + 36,
  FETCHINFO_RTSP_CLIENT_CSEQ = FETCHINFO_LONG   + 37,
  FETCHINFO_RTSP_SERVER_CSEQ = FETCHINFO_LONG   + 38,
  FETCHINFO_RTSP_CSEQ_RECV   = FETCHINFO_LONG   + 39,
  FETCHINFO_PRIMARY_PORT     = FETCHINFO_LONG   + 40,
  FETCHINFO_LOCAL_IP         = FETCHINFO_STRING + 41,
  FETCHINFO_LOCAL_PORT       = FETCHINFO_LONG   + 42,
  FETCHINFO_TLS_SESSION FETCH_DEPRECATED(7.48.0, "Use FETCHINFO_TLS_SSL_PTR")
                            = FETCHINFO_PTR    + 43,
  FETCHINFO_ACTIVESOCKET     = FETCHINFO_SOCKET + 44,
  FETCHINFO_TLS_SSL_PTR      = FETCHINFO_PTR    + 45,
  FETCHINFO_HTTP_VERSION     = FETCHINFO_LONG   + 46,
  FETCHINFO_PROXY_SSL_VERIFYRESULT = FETCHINFO_LONG + 47,
  FETCHINFO_PROTOCOL    FETCH_DEPRECATED(7.85.0, "Use FETCHINFO_SCHEME")
                            = FETCHINFO_LONG   + 48,
  FETCHINFO_SCHEME           = FETCHINFO_STRING + 49,
  FETCHINFO_TOTAL_TIME_T     = FETCHINFO_OFF_T + 50,
  FETCHINFO_NAMELOOKUP_TIME_T = FETCHINFO_OFF_T + 51,
  FETCHINFO_CONNECT_TIME_T   = FETCHINFO_OFF_T + 52,
  FETCHINFO_PRETRANSFER_TIME_T = FETCHINFO_OFF_T + 53,
  FETCHINFO_STARTTRANSFER_TIME_T = FETCHINFO_OFF_T + 54,
  FETCHINFO_REDIRECT_TIME_T  = FETCHINFO_OFF_T + 55,
  FETCHINFO_APPCONNECT_TIME_T = FETCHINFO_OFF_T + 56,
  FETCHINFO_RETRY_AFTER      = FETCHINFO_OFF_T + 57,
  FETCHINFO_EFFECTIVE_METHOD = FETCHINFO_STRING + 58,
  FETCHINFO_PROXY_ERROR      = FETCHINFO_LONG + 59,
  FETCHINFO_REFERER          = FETCHINFO_STRING + 60,
  FETCHINFO_CAINFO           = FETCHINFO_STRING + 61,
  FETCHINFO_CAPATH           = FETCHINFO_STRING + 62,
  FETCHINFO_XFER_ID          = FETCHINFO_OFF_T + 63,
  FETCHINFO_CONN_ID          = FETCHINFO_OFF_T + 64,
  FETCHINFO_QUEUE_TIME_T     = FETCHINFO_OFF_T + 65,
  FETCHINFO_USED_PROXY       = FETCHINFO_LONG + 66,
  FETCHINFO_POSTTRANSFER_TIME_T = FETCHINFO_OFF_T + 67,
  FETCHINFO_EARLYDATA_SENT_T = FETCHINFO_OFF_T + 68,
  FETCHINFO_HTTPAUTH_USED    = FETCHINFO_LONG + 69,
  FETCHINFO_PROXYAUTH_USED   = FETCHINFO_LONG + 70,
  FETCHINFO_LASTONE          = 70
} FETCHINFO;

/* FETCHINFO_RESPONSE_CODE is the new name for the option previously known as
   FETCHINFO_HTTP_CODE */
#define FETCHINFO_HTTP_CODE FETCHINFO_RESPONSE_CODE

typedef enum {
  FETCHCLOSEPOLICY_NONE, /* first, never use this */

  FETCHCLOSEPOLICY_OLDEST,
  FETCHCLOSEPOLICY_LEAST_RECENTLY_USED,
  FETCHCLOSEPOLICY_LEAST_TRAFFIC,
  FETCHCLOSEPOLICY_SLOWEST,
  FETCHCLOSEPOLICY_CALLBACK,

  FETCHCLOSEPOLICY_LAST /* last, never use this */
} fetch_closepolicy;

#define FETCH_GLOBAL_SSL (1<<0) /* no purpose since 7.57.0 */
#define FETCH_GLOBAL_WIN32 (1<<1)
#define FETCH_GLOBAL_ALL (FETCH_GLOBAL_SSL|FETCH_GLOBAL_WIN32)
#define FETCH_GLOBAL_NOTHING 0
#define FETCH_GLOBAL_DEFAULT FETCH_GLOBAL_ALL
#define FETCH_GLOBAL_ACK_EINTR (1<<2)


/*****************************************************************************
 * Setup defines, protos etc for the sharing stuff.
 */

/* Different data locks for a single share */
typedef enum {
  FETCH_LOCK_DATA_NONE = 0,
  /*  FETCH_LOCK_DATA_SHARE is used internally to say that
   *  the locking is just made to change the internal state of the share
   *  itself.
   */
  FETCH_LOCK_DATA_SHARE,
  FETCH_LOCK_DATA_COOKIE,
  FETCH_LOCK_DATA_DNS,
  FETCH_LOCK_DATA_SSL_SESSION,
  FETCH_LOCK_DATA_CONNECT,
  FETCH_LOCK_DATA_PSL,
  FETCH_LOCK_DATA_HSTS,
  FETCH_LOCK_DATA_LAST
} fetch_lock_data;

/* Different lock access types */
typedef enum {
  FETCH_LOCK_ACCESS_NONE = 0,   /* unspecified action */
  FETCH_LOCK_ACCESS_SHARED = 1, /* for read perhaps */
  FETCH_LOCK_ACCESS_SINGLE = 2, /* for write perhaps */
  FETCH_LOCK_ACCESS_LAST        /* never use */
} fetch_lock_access;

typedef void (*fetch_lock_function)(FETCH *handle,
                                   fetch_lock_data data,
                                   fetch_lock_access locktype,
                                   void *userptr);
typedef void (*fetch_unlock_function)(FETCH *handle,
                                     fetch_lock_data data,
                                     void *userptr);


typedef enum {
  FETCHSHE_OK,  /* all is fine */
  FETCHSHE_BAD_OPTION, /* 1 */
  FETCHSHE_IN_USE,     /* 2 */
  FETCHSHE_INVALID,    /* 3 */
  FETCHSHE_NOMEM,      /* 4 out of memory */
  FETCHSHE_NOT_BUILT_IN, /* 5 feature not present in lib */
  FETCHSHE_LAST        /* never use */
} FETCHSHcode;

typedef enum {
  FETCHSHOPT_NONE,  /* do not use */
  FETCHSHOPT_SHARE,   /* specify a data type to share */
  FETCHSHOPT_UNSHARE, /* specify which data type to stop sharing */
  FETCHSHOPT_LOCKFUNC,   /* pass in a 'fetch_lock_function' pointer */
  FETCHSHOPT_UNLOCKFUNC, /* pass in a 'fetch_unlock_function' pointer */
  FETCHSHOPT_USERDATA,   /* pass in a user data pointer used in the lock/unlock
                           callback functions */
  FETCHSHOPT_LAST  /* never use */
} FETCHSHoption;

FETCH_EXTERN FETCHSH *fetch_share_init(void);
FETCH_EXTERN FETCHSHcode fetch_share_setopt(FETCHSH *share, FETCHSHoption option,
                                         ...);
FETCH_EXTERN FETCHSHcode fetch_share_cleanup(FETCHSH *share);

/****************************************************************************
 * Structures for querying information about the fetch library at runtime.
 */

typedef enum {
  FETCHVERSION_FIRST,    /* 7.10 */
  FETCHVERSION_SECOND,   /* 7.11.1 */
  FETCHVERSION_THIRD,    /* 7.12.0 */
  FETCHVERSION_FOURTH,   /* 7.16.1 */
  FETCHVERSION_FIFTH,    /* 7.57.0 */
  FETCHVERSION_SIXTH,    /* 7.66.0 */
  FETCHVERSION_SEVENTH,  /* 7.70.0 */
  FETCHVERSION_EIGHTH,   /* 7.72.0 */
  FETCHVERSION_NINTH,    /* 7.75.0 */
  FETCHVERSION_TENTH,    /* 7.77.0 */
  FETCHVERSION_ELEVENTH, /* 7.87.0 */
  FETCHVERSION_TWELFTH,  /* 8.8.0 */
  FETCHVERSION_LAST /* never actually use this */
} FETCHversion;

/* The 'FETCHVERSION_NOW' is the symbolic name meant to be used by
   basically all programs ever that want to get version information. It is
   meant to be a built-in version number for what kind of struct the caller
   expects. If the struct ever changes, we redefine the NOW to another enum
   from above. */
#define FETCHVERSION_NOW FETCHVERSION_TWELFTH

struct fetch_version_info_data {
  FETCHversion age;          /* age of the returned struct */
  const char *version;      /* LIBFETCH_VERSION */
  unsigned int version_num; /* LIBFETCH_VERSION_NUM */
  const char *host;         /* OS/host/cpu/machine when configured */
  int features;             /* bitmask, see defines below */
  const char *ssl_version;  /* human readable string */
  long ssl_version_num;     /* not used anymore, always 0 */
  const char *libz_version; /* human readable string */
  /* protocols is terminated by an entry with a NULL protoname */
  const char * const *protocols;

  /* The fields below this were added in FETCHVERSION_SECOND */
  const char *ares;
  int ares_num;

  /* This field was added in FETCHVERSION_THIRD */
  const char *libidn;

  /* These field were added in FETCHVERSION_FOURTH */

  /* Same as '_libiconv_version' if built with HAVE_ICONV */
  int iconv_ver_num;

  const char *libssh_version; /* human readable string */

  /* These fields were added in FETCHVERSION_FIFTH */
  unsigned int brotli_ver_num; /* Numeric Brotli version
                                  (MAJOR << 24) | (MINOR << 12) | PATCH */
  const char *brotli_version; /* human readable string. */

  /* These fields were added in FETCHVERSION_SIXTH */
  unsigned int nghttp2_ver_num; /* Numeric nghttp2 version
                                   (MAJOR << 16) | (MINOR << 8) | PATCH */
  const char *nghttp2_version; /* human readable string. */
  const char *quic_version;    /* human readable quic (+ HTTP/3) library +
                                  version or NULL */

  /* These fields were added in FETCHVERSION_SEVENTH */
  const char *cainfo;          /* the built-in default FETCHOPT_CAINFO, might
                                  be NULL */
  const char *capath;          /* the built-in default FETCHOPT_CAPATH, might
                                  be NULL */

  /* These fields were added in FETCHVERSION_EIGHTH */
  unsigned int zstd_ver_num; /* Numeric Zstd version
                                  (MAJOR << 24) | (MINOR << 12) | PATCH */
  const char *zstd_version; /* human readable string. */

  /* These fields were added in FETCHVERSION_NINTH */
  const char *hyper_version; /* human readable string. */

  /* These fields were added in FETCHVERSION_TENTH */
  const char *gsasl_version; /* human readable string. */

  /* These fields were added in FETCHVERSION_ELEVENTH */
  /* feature_names is terminated by an entry with a NULL feature name */
  const char * const *feature_names;

  /* These fields were added in FETCHVERSION_TWELFTH */
  const char *rtmp_version; /* human readable string. */
};
typedef struct fetch_version_info_data fetch_version_info_data;

#define FETCH_VERSION_IPV6         (1<<0)  /* IPv6-enabled */
#define FETCH_VERSION_KERBEROS4    (1<<1)  /* Kerberos V4 auth is supported
                                             (deprecated) */
#define FETCH_VERSION_SSL          (1<<2)  /* SSL options are present */
#define FETCH_VERSION_LIBZ         (1<<3)  /* libz features are present */
#define FETCH_VERSION_NTLM         (1<<4)  /* NTLM auth is supported */
#define FETCH_VERSION_GSSNEGOTIATE (1<<5)  /* Negotiate auth is supported
                                             (deprecated) */
#define FETCH_VERSION_DEBUG        (1<<6)  /* Built with debug capabilities */
#define FETCH_VERSION_ASYNCHDNS    (1<<7)  /* Asynchronous DNS resolves */
#define FETCH_VERSION_SPNEGO       (1<<8)  /* SPNEGO auth is supported */
#define FETCH_VERSION_LARGEFILE    (1<<9)  /* Supports files larger than 2GB */
#define FETCH_VERSION_IDN          (1<<10) /* Internationized Domain Names are
                                             supported */
#define FETCH_VERSION_SSPI         (1<<11) /* Built against Windows SSPI */
#define FETCH_VERSION_CONV         (1<<12) /* Character conversions supported */
#define FETCH_VERSION_FETCHDEBUG    (1<<13) /* Debug memory tracking supported */
#define FETCH_VERSION_TLSAUTH_SRP  (1<<14) /* TLS-SRP auth is supported */
#define FETCH_VERSION_NTLM_WB      (1<<15) /* NTLM delegation to winbind helper
                                             is supported */
#define FETCH_VERSION_HTTP2        (1<<16) /* HTTP2 support built-in */
#define FETCH_VERSION_GSSAPI       (1<<17) /* Built against a GSS-API library */
#define FETCH_VERSION_KERBEROS5    (1<<18) /* Kerberos V5 auth is supported */
#define FETCH_VERSION_UNIX_SOCKETS (1<<19) /* Unix domain sockets support */
#define FETCH_VERSION_PSL          (1<<20) /* Mozilla's Public Suffix List, used
                                             for cookie domain verification */
#define FETCH_VERSION_HTTPS_PROXY  (1<<21) /* HTTPS-proxy support built-in */
#define FETCH_VERSION_MULTI_SSL    (1<<22) /* Multiple SSL backends available */
#define FETCH_VERSION_BROTLI       (1<<23) /* Brotli features are present. */
#define FETCH_VERSION_ALTSVC       (1<<24) /* Alt-Svc handling built-in */
#define FETCH_VERSION_HTTP3        (1<<25) /* HTTP3 support built-in */
#define FETCH_VERSION_ZSTD         (1<<26) /* zstd features are present */
#define FETCH_VERSION_UNICODE      (1<<27) /* Unicode support on Windows */
#define FETCH_VERSION_HSTS         (1<<28) /* HSTS is supported */
#define FETCH_VERSION_GSASL        (1<<29) /* libgsasl is supported */
#define FETCH_VERSION_THREADSAFE   (1<<30) /* libfetch API is thread-safe */

/*
 * NAME fetch_version_info()
 *
 * DESCRIPTION
 *
 * This function returns a pointer to a static copy of the version info
 * struct. See above.
 */
FETCH_EXTERN fetch_version_info_data *fetch_version_info(FETCHversion);

/*
 * NAME fetch_easy_strerror()
 *
 * DESCRIPTION
 *
 * The fetch_easy_strerror function may be used to turn a FETCHcode value
 * into the equivalent human readable error string. This is useful
 * for printing meaningful error messages.
 */
FETCH_EXTERN const char *fetch_easy_strerror(FETCHcode);

/*
 * NAME fetch_share_strerror()
 *
 * DESCRIPTION
 *
 * The fetch_share_strerror function may be used to turn a FETCHSHcode value
 * into the equivalent human readable error string. This is useful
 * for printing meaningful error messages.
 */
FETCH_EXTERN const char *fetch_share_strerror(FETCHSHcode);

/*
 * NAME fetch_easy_pause()
 *
 * DESCRIPTION
 *
 * The fetch_easy_pause function pauses or unpauses transfers. Select the new
 * state by setting the bitmask, use the convenience defines below.
 *
 */
FETCH_EXTERN FETCHcode fetch_easy_pause(FETCH *handle, int bitmask);

#define FETCHPAUSE_RECV      (1<<0)
#define FETCHPAUSE_RECV_CONT (0)

#define FETCHPAUSE_SEND      (1<<2)
#define FETCHPAUSE_SEND_CONT (0)

#define FETCHPAUSE_ALL       (FETCHPAUSE_RECV|FETCHPAUSE_SEND)
#define FETCHPAUSE_CONT      (FETCHPAUSE_RECV_CONT|FETCHPAUSE_SEND_CONT)

/*
 * NAME fetch_easy_ssls_import()
 *
 * DESCRIPTION
 *
 * The fetch_easy_ssls_import function adds a previously exported SSL session
 * to the SSL session cache of the easy handle (or the underlying share).
 */
FETCH_EXTERN FETCHcode fetch_easy_ssls_import(FETCH *handle,
                                           const char *session_key,
                                           const unsigned char *shmac,
                                           size_t shmac_len,
                                           const unsigned char *sdata,
                                           size_t sdata_len);

/* This is the fetch_ssls_export_cb callback prototype. It
 * is passed to fetch_easy_ssls_export() to extract SSL sessions/tickets. */
typedef FETCHcode fetch_ssls_export_cb(FETCH *handle,
                                     void *userptr,
                                     const char *session_key,
                                     const unsigned char *shmac,
                                     size_t shmac_len,
                                     const unsigned char *sdata,
                                     size_t sdata_len,
                                     fetch_off_t valid_until,
                                     int ietf_tls_id,
                                     const char *alpn,
                                     size_t earlydata_max);

/*
 * NAME fetch_easy_ssls_export()
 *
 * DESCRIPTION
 *
 * The fetch_easy_ssls_export function iterates over all SSL sessions stored
 * in the easy handle (or underlying share) and invokes the passed
 * callback.
 *
 */
FETCH_EXTERN FETCHcode fetch_easy_ssls_export(FETCH *handle,
                                           fetch_ssls_export_cb *export_fn,
                                           void *userptr);


#ifdef  __cplusplus
} /* end of extern "C" */
#endif

/* unfortunately, the easy.h and multi.h include files need options and info
  stuff before they can be included! */
#include "easy.h" /* nothing in fetch is fun without the easy stuff */
#include "multi.h"
#include "urlapi.h"
#include "options.h"
#include "header.h"
#include "websockets.h"
#ifndef FETCH_SKIP_INCLUDE_MPRINTF
#include "mprintf.h"
#endif

/* the typechecker does not work in C++ (yet) */
#if defined(__GNUC__) && defined(__GNUC_MINOR__) && \
    ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)) && \
    !defined(__cplusplus) && !defined(FETCH_DISABLE_TYPECHECK)
#include "typecheck-gcc.h"
#else
#if defined(__STDC__) && (__STDC__ >= 1)
/* This preprocessor magic that replaces a call with the exact same call is
   only done to make sure application authors pass exactly three arguments
   to these functions. */
#define fetch_easy_setopt(handle,opt,param) fetch_easy_setopt(handle,opt,param)
#define fetch_easy_getinfo(handle,info,arg) fetch_easy_getinfo(handle,info,arg)
#define fetch_share_setopt(share,opt,param) fetch_share_setopt(share,opt,param)
#define fetch_multi_setopt(handle,opt,param) fetch_multi_setopt(handle,opt,param)
#endif /* __STDC__ >= 1 */
#endif /* gcc >= 4.3 && !__cplusplus && !FETCH_DISABLE_TYPECHECK */

#endif /* FETCHINC_FETCH_H */
