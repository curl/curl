/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "setup.h"

/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "strequal.h"

#ifdef WIN32
#include <time.h>
#include <io.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#endif  /* WIN32 ... */

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "sslgen.h"
#include "url.h"
#include "getinfo.h"
#include "hostip.h"
#include "share.h"
#include "strdup.h"
#include "curl_memory.h"
#include "progress.h"
#include "easyif.h"
#include "select.h"
#include "sendf.h" /* for failf function prototype */
#include "http_ntlm.h"
#include "connect.h" /* for Curl_getconnectinfo */
#include "slist.h"
#include "curl_rand.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#if defined(CURL_DOES_CONVERSIONS) && defined(HAVE_ICONV)
#include <iconv.h>
/* set default codesets for iconv */
#ifndef CURL_ICONV_CODESET_OF_NETWORK
#define CURL_ICONV_CODESET_OF_NETWORK "ISO8859-1"
#endif
#ifndef CURL_ICONV_CODESET_FOR_UTF8
#define CURL_ICONV_CODESET_FOR_UTF8   "UTF-8"
#endif
#define ICONV_ERROR  (size_t)-1
#endif /* CURL_DOES_CONVERSIONS && HAVE_ICONV */

/* The last #include file should be: */
#include "memdebug.h"

/* win32_cleanup() is for win32 socket cleanup functionality, the opposite
   of win32_init() */
static void win32_cleanup(void)
{
#ifdef USE_WINSOCK
  WSACleanup();
#endif
#ifdef USE_WINDOWS_SSPI
  Curl_sspi_global_cleanup();
#endif
}

/* win32_init() performs win32 socket initialization to properly setup the
   stack to allow networking */
static CURLcode win32_init(void)
{
#ifdef USE_WINSOCK
  WORD wVersionRequested;
  WSADATA wsaData;
  int res;

#if defined(ENABLE_IPV6) && (USE_WINSOCK < 2)
  Error IPV6_requires_winsock2
#endif

  wVersionRequested = MAKEWORD(USE_WINSOCK, USE_WINSOCK);

  res = WSAStartup(wVersionRequested, &wsaData);

  if(res != 0)
    /* Tell the user that we couldn't find a useable */
    /* winsock.dll.     */
    return CURLE_FAILED_INIT;

  /* Confirm that the Windows Sockets DLL supports what we need.*/
  /* Note that if the DLL supports versions greater */
  /* than wVersionRequested, it will still return */
  /* wVersionRequested in wVersion. wHighVersion contains the */
  /* highest supported version. */

  if( LOBYTE( wsaData.wVersion ) != LOBYTE(wVersionRequested) ||
       HIBYTE( wsaData.wVersion ) != HIBYTE(wVersionRequested) ) {
    /* Tell the user that we couldn't find a useable */

    /* winsock.dll. */
    WSACleanup();
    return CURLE_FAILED_INIT;
  }
  /* The Windows Sockets DLL is acceptable. Proceed. */
#endif

#ifdef USE_WINDOWS_SSPI
  {
    CURLcode err = Curl_sspi_global_init();
    if (err != CURLE_OK)
      return err;
  }
#endif

  return CURLE_OK;
}

#ifdef USE_LIBIDN
/*
 * Initialise use of IDNA library.
 * It falls back to ASCII if $CHARSET isn't defined. This doesn't work for
 * idna_to_ascii_lz().
 */
static void idna_init (void)
{
#ifdef WIN32
  char buf[60];
  UINT cp = GetACP();

  if(!getenv("CHARSET") && cp > 0) {
    snprintf(buf, sizeof(buf), "CHARSET=cp%u", cp);
    putenv(buf);
  }
#else
  /* to do? */
#endif
}
#endif  /* USE_LIBIDN */

/* true globals -- for curl_global_init() and curl_global_cleanup() */
static unsigned int  initialized;
static long          init_flags;

/*
 * strdup (and other memory functions) is redefined in complicated
 * ways, but at this point it must be defined as the system-supplied strdup
 * so the callback pointer is initialized correctly.
 */
#if defined(_WIN32_WCE)
#define system_strdup _strdup
#elif !defined(HAVE_STRDUP)
#define system_strdup curlx_strdup
#else
#define system_strdup strdup
#endif

#if defined(_MSC_VER) && defined(_DLL) && !defined(__POCC__)
#  pragma warning(disable:4232) /* MSVC extension, dllimport identity */
#endif

#ifndef __SYMBIAN32__
/*
 * If a memory-using function (like curl_getenv) is used before
 * curl_global_init() is called, we need to have these pointers set already.
 */
curl_malloc_callback Curl_cmalloc = (curl_malloc_callback)malloc;
curl_free_callback Curl_cfree = (curl_free_callback)free;
curl_realloc_callback Curl_crealloc = (curl_realloc_callback)realloc;
curl_strdup_callback Curl_cstrdup = (curl_strdup_callback)system_strdup;
curl_calloc_callback Curl_ccalloc = (curl_calloc_callback)calloc;
#else
/*
 * Symbian OS doesn't support initialization to code in writeable static data.
 * Initialization will occur in the curl_global_init() call.
 */
curl_malloc_callback Curl_cmalloc;
curl_free_callback Curl_cfree;
curl_realloc_callback Curl_crealloc;
curl_strdup_callback Curl_cstrdup;
curl_calloc_callback Curl_ccalloc;
#endif

#if defined(_MSC_VER) && defined(_DLL) && !defined(__POCC__)
#  pragma warning(default:4232) /* MSVC extension, dllimport identity */
#endif

/**
 * curl_global_init() globally initializes cURL given a bitwise set of the
 * different features of what to initialize.
 */
CURLcode curl_global_init(long flags)
{
  if(initialized++)
    return CURLE_OK;

  /* Setup the default memory functions here (again) */
  Curl_cmalloc = (curl_malloc_callback)malloc;
  Curl_cfree = (curl_free_callback)free;
  Curl_crealloc = (curl_realloc_callback)realloc;
  Curl_cstrdup = (curl_strdup_callback)system_strdup;
  Curl_ccalloc = (curl_calloc_callback)calloc;

  if(flags & CURL_GLOBAL_SSL)
    if(!Curl_ssl_init()) {
      DEBUGF(fprintf(stderr, "Error: Curl_ssl_init failed\n"));
      return CURLE_FAILED_INIT;
    }

  if(flags & CURL_GLOBAL_WIN32)
    if(win32_init() != CURLE_OK) {
      DEBUGF(fprintf(stderr, "Error: win32_init failed\n"));
      return CURLE_FAILED_INIT;
    }

#ifdef __AMIGA__
  if(!amiga_init()) {
    DEBUGF(fprintf(stderr, "Error: amiga_init failed\n"));
    return CURLE_FAILED_INIT;
  }
#endif

#ifdef NETWARE
  if(netware_init()) {
    DEBUGF(fprintf(stderr, "Warning: LONG namespace not available\n"));
  }
#endif

#ifdef USE_LIBIDN
  idna_init();
#endif

#ifdef CARES_HAVE_ARES_LIBRARY_INIT
  if(ares_library_init(ARES_LIB_INIT_ALL)) {
    DEBUGF(fprintf(stderr, "Error: ares_library_init failed\n"));
    return CURLE_FAILED_INIT;
  }
#endif

#if defined(USE_LIBSSH2) && defined(HAVE_LIBSSH2_INIT)
  if(libssh2_init(0)) {
    DEBUGF(fprintf(stderr, "Error: libssh2_init failed\n"));
    return CURLE_FAILED_INIT;
  }
#endif

  init_flags  = flags;

  /* Preset pseudo-random number sequence. */

  Curl_srand();

  return CURLE_OK;
}

/*
 * curl_global_init_mem() globally initializes cURL and also registers the
 * user provided callback routines.
 */
CURLcode curl_global_init_mem(long flags, curl_malloc_callback m,
                              curl_free_callback f, curl_realloc_callback r,
                              curl_strdup_callback s, curl_calloc_callback c)
{
  CURLcode code = CURLE_OK;

  /* Invalid input, return immediately */
  if(!m || !f || !r || !s || !c)
    return CURLE_FAILED_INIT;

  /* Already initialized, don't do it again */
  if( initialized )
    return CURLE_OK;

  /* Call the actual init function first */
  code = curl_global_init(flags);
  if(code == CURLE_OK) {
    Curl_cmalloc = m;
    Curl_cfree = f;
    Curl_cstrdup = s;
    Curl_crealloc = r;
    Curl_ccalloc = c;
  }

  return code;
}

/**
 * curl_global_cleanup() globally cleanups cURL, uses the value of
 * "init_flags" to determine what needs to be cleaned up and what doesn't.
 */
void curl_global_cleanup(void)
{
  if(!initialized)
    return;

  if(--initialized)
    return;

  Curl_global_host_cache_dtor();

  if(init_flags & CURL_GLOBAL_SSL)
    Curl_ssl_cleanup();

#ifdef CARES_HAVE_ARES_LIBRARY_CLEANUP
  ares_library_cleanup();
#endif

  if(init_flags & CURL_GLOBAL_WIN32)
    win32_cleanup();

#ifdef __AMIGA__
  amiga_cleanup();
#endif

#if defined(USE_LIBSSH2) && defined(HAVE_LIBSSH2_EXIT)
  (void)libssh2_exit();
#endif

  init_flags  = 0;
}

/*
 * curl_easy_init() is the external interface to alloc, setup and init an
 * easy handle that is returned. If anything goes wrong, NULL is returned.
 */
CURL *curl_easy_init(void)
{
  CURLcode res;
  struct SessionHandle *data;

  /* Make sure we inited the global SSL stuff */
  if(!initialized) {
    res = curl_global_init(CURL_GLOBAL_DEFAULT);
    if(res) {
      /* something in the global init failed, return nothing */
      DEBUGF(fprintf(stderr, "Error: curl_global_init failed\n"));
      return NULL;
    }
  }

  /* We use curl_open() with undefined URL so far */
  res = Curl_open(&data);
  if(res != CURLE_OK) {
    DEBUGF(fprintf(stderr, "Error: Curl_open failed\n"));
    return NULL;
  }

  return data;
}

/*
 * curl_easy_setopt() is the external interface for setting options on an
 * easy handle.
 */

#undef curl_easy_setopt
CURLcode curl_easy_setopt(CURL *curl, CURLoption tag, ...)
{
  va_list arg;
  struct SessionHandle *data = curl;
  CURLcode ret;

  if(!curl)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  va_start(arg, tag);

  ret = Curl_setopt(data, tag, arg);

  va_end(arg);
  return ret;
}

#ifdef CURL_MULTIEASY
/***************************************************************************
 * This function is still only for testing purposes. It makes a great way
 * to run the full test suite on the multi interface instead of the easy one.
 ***************************************************************************
 *
 * The *new* curl_easy_perform() is the external interface that performs a
 * transfer previously setup.
 *
 * Wrapper-function that: creates a multi handle, adds the easy handle to it,
 * runs curl_multi_perform() until the transfer is done, then detaches the
 * easy handle, destroys the multi handle and returns the easy handle's return
 * code. This will make everything internally use and assume multi interface.
 */
CURLcode curl_easy_perform(CURL *easy)
{
  CURLM *multi;
  CURLMcode mcode;
  CURLcode code = CURLE_OK;
  int still_running;
  struct timeval timeout;
  int rc;
  CURLMsg *msg;
  fd_set fdread;
  fd_set fdwrite;
  fd_set fdexcep;
  int maxfd;

  if(!easy)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  multi = curl_multi_init();
  if(!multi)
    return CURLE_OUT_OF_MEMORY;

  mcode = curl_multi_add_handle(multi, easy);
  if(mcode) {
    curl_multi_cleanup(multi);
    if(mcode == CURLM_OUT_OF_MEMORY)
      return CURLE_OUT_OF_MEMORY;
    else
      return CURLE_FAILED_INIT;
  }

  /* we start some action by calling perform right away */

  do {
    while(CURLM_CALL_MULTI_PERFORM ==
          curl_multi_perform(multi, &still_running));

    if(!still_running)
      break;

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    /* timeout once per second */
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    /* Old deprecated style: get file descriptors from the transfers */
    curl_multi_fdset(multi, &fdread, &fdwrite, &fdexcep, &maxfd);
    rc = Curl_select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);

    /* The way is to extract the sockets and wait for them without using
       select. This whole alternative version should probably rather use the
       curl_multi_socket() approach. */

    if(rc == -1)
      /* select error */
      break;

    /* timeout or data to send/receive => loop! */
  } while(still_running);

  msg = curl_multi_info_read(multi, &rc);
  if(msg)
    code = msg->data.result;

  mcode = curl_multi_remove_handle(multi, easy);
  /* what to do if it fails? */

  mcode = curl_multi_cleanup(multi);
  /* what to do if it fails? */

  return code;
}
#else
/*
 * curl_easy_perform() is the external interface that performs a transfer
 * previously setup.
 */
CURLcode curl_easy_perform(CURL *curl)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;

  if(!data)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if( ! (data->share && data->share->hostcache) ) {
    /* this handle is not using a shared dns cache */

    if(data->set.global_dns_cache &&
       (data->dns.hostcachetype != HCACHE_GLOBAL)) {
      /* global dns cache was requested but still isn't */
      struct curl_hash *ptr;

      if(data->dns.hostcachetype == HCACHE_PRIVATE) {
        /* if the current cache is private, kill it first */
        Curl_hash_destroy(data->dns.hostcache);
        data->dns.hostcachetype = HCACHE_NONE;
        data->dns.hostcache = NULL;
      }

      ptr = Curl_global_host_cache_init();
      if(ptr) {
        /* only do this if the global cache init works */
        data->dns.hostcache = ptr;
        data->dns.hostcachetype = HCACHE_GLOBAL;
      }
    }

    if(!data->dns.hostcache) {
      data->dns.hostcachetype = HCACHE_PRIVATE;
      data->dns.hostcache = Curl_mk_dnscache();

      if(!data->dns.hostcache)
        /* While we possibly could survive and do good without a host cache,
           the fact that creating it failed indicates that things are truly
           screwed up and we should bail out! */
        return CURLE_OUT_OF_MEMORY;
    }

  }

  if(!data->state.connc) {
    /* oops, no connection cache, make one up */
    data->state.connc = Curl_mk_connc(CONNCACHE_PRIVATE, -1L);
    if(!data->state.connc)
      return CURLE_OUT_OF_MEMORY;
  }

  return Curl_perform(data);
}
#endif

/*
 * curl_easy_cleanup() is the external interface to cleaning/freeing the given
 * easy handle.
 */
void curl_easy_cleanup(CURL *curl)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;

  if(!data)
    return;

  Curl_close(data);
}

/*
 * Store a pointed to the multi handle within the easy handle's data struct.
 */
void Curl_easy_addmulti(struct SessionHandle *data,
                        void *multi)
{
  data->multi = multi;
  if(multi == NULL)
    /* the association is cleared, mark the easy handle as not used by an
       interface */
    data->state.used_interface = Curl_if_none;
}

void Curl_easy_initHandleData(struct SessionHandle *data)
{
    memset(&data->req, 0, sizeof(struct SingleRequest));

    data->req.maxdownload = -1;
}

/*
 * curl_easy_getinfo() is an external interface that allows an app to retrieve
 * information from a performed transfer and similar.
 */
#undef curl_easy_getinfo
CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...)
{
  va_list arg;
  void *paramp;
  struct SessionHandle *data = (struct SessionHandle *)curl;

  va_start(arg, info);
  paramp = va_arg(arg, void *);

  return Curl_getinfo(data, info, paramp);
}

/*
 * curl_easy_duphandle() is an external interface to allow duplication of a
 * given input easy handle. The returned handle will be a new working handle
 * with all options set exactly as the input source handle.
 */
CURL *curl_easy_duphandle(CURL *incurl)
{
  bool fail = TRUE;
  struct SessionHandle *data=(struct SessionHandle *)incurl;

  struct SessionHandle *outcurl = calloc(1, sizeof(struct SessionHandle));

  if(NULL == outcurl)
    return NULL; /* failure */

  do {

    /*
     * We setup a few buffers we need. We should probably make them
     * get setup on-demand in the code, as that would probably decrease
     * the likeliness of us forgetting to init a buffer here in the future.
     */
    outcurl->state.headerbuff = malloc(HEADERSIZE);
    if(!outcurl->state.headerbuff) {
      break;
    }
    outcurl->state.headersize=HEADERSIZE;

    /* copy all userdefined values */
    if(Curl_dupset(outcurl, data) != CURLE_OK)
      break;

    /* the connection cache is setup on demand */
    outcurl->state.connc = NULL;

    outcurl->state.lastconnect = -1;

    outcurl->progress.flags    = data->progress.flags;
    outcurl->progress.callback = data->progress.callback;

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
    if(data->cookies) {
      /* If cookies are enabled in the parent handle, we enable them
         in the clone as well! */
      outcurl->cookies = Curl_cookie_init(data,
                                          data->cookies->filename,
                                          outcurl->cookies,
                                          data->set.cookiesession);
      if(!outcurl->cookies) {
        break;
      }
    }
#endif   /* CURL_DISABLE_HTTP */

    /* duplicate all values in 'change' */

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
    if(data->change.cookielist) {
      outcurl->change.cookielist =
        Curl_slist_duplicate(data->change.cookielist);

      if (!outcurl->change.cookielist)
        break;
    }
#endif   /* CURL_DISABLE_HTTP */

    if(data->change.url) {
      outcurl->change.url = strdup(data->change.url);
      if(!outcurl->change.url)
        break;
      outcurl->change.url_alloc = TRUE;
    }

    if(data->change.referer) {
      outcurl->change.referer = strdup(data->change.referer);
      if(!outcurl->change.referer)
        break;
      outcurl->change.referer_alloc = TRUE;
    }

#ifdef USE_ARES
    /* If we use ares, we clone the ares channel for the new handle */
    if(ARES_SUCCESS != ares_dup(&outcurl->state.areschannel,
                                data->state.areschannel))
      break;
#endif

#if defined(CURL_DOES_CONVERSIONS) && defined(HAVE_ICONV)
    outcurl->inbound_cd = iconv_open(CURL_ICONV_CODESET_OF_HOST,
                                     CURL_ICONV_CODESET_OF_NETWORK);
    outcurl->outbound_cd = iconv_open(CURL_ICONV_CODESET_OF_NETWORK,
                                      CURL_ICONV_CODESET_OF_HOST);
    outcurl->utf8_cd = iconv_open(CURL_ICONV_CODESET_OF_HOST,
                                  CURL_ICONV_CODESET_FOR_UTF8);
#endif

    Curl_easy_initHandleData(outcurl);

    outcurl->magic = CURLEASY_MAGIC_NUMBER;

    fail = FALSE; /* we reach this point and thus we are OK */

  } while(0);

  if(fail) {
    if(outcurl) {
      if(outcurl->state.connc &&
         (outcurl->state.connc->type == CONNCACHE_PRIVATE))
        Curl_rm_connc(outcurl->state.connc);
      if(outcurl->state.headerbuff)
        free(outcurl->state.headerbuff);
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
      if(outcurl->change.cookielist)
        curl_slist_free_all(outcurl->change.cookielist);
#endif
      if(outcurl->change.url)
        free(outcurl->change.url);
      if(outcurl->change.referer)
        free(outcurl->change.referer);
      Curl_freeset(outcurl);
      free(outcurl); /* free the memory again */
      outcurl = NULL;
    }
  }

  return outcurl;
}

/*
 * curl_easy_reset() is an external interface that allows an app to re-
 * initialize a session handle to the default values.
 */
void curl_easy_reset(CURL *curl)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;

  Curl_safefree(data->state.pathbuffer);
  data->state.pathbuffer=NULL;

  Curl_safefree(data->state.proto.generic);
  data->state.proto.generic=NULL;

  /* zero out UserDefined data: */
  Curl_freeset(data);
  memset(&data->set, 0, sizeof(struct UserDefined));
  (void)Curl_init_userdefined(&data->set);

  /* zero out Progress data: */
  memset(&data->progress, 0, sizeof(struct Progress));

  /* init Handle data */
  Curl_easy_initHandleData(data);

  data->progress.flags |= PGRS_HIDE;
  data->state.current_speed = -1; /* init to negative == impossible */
}

/*
 * curl_easy_pause() allows an application to pause or unpause a specific
 * transfer and direction. This function sets the full new state for the
 * current connection this easy handle operates on.
 *
 * NOTE: if you have the receiving paused and you call this function to remove
 * the pausing, you may get your write callback called at this point.
 *
 * Action is a bitmask consisting of CURLPAUSE_* bits in curl/curl.h
 */
CURLcode curl_easy_pause(CURL *curl, int action)
{
  struct SessionHandle *data = (struct SessionHandle *)curl;
  struct SingleRequest *k = &data->req;
  CURLcode result = CURLE_OK;

  /* first switch off both pause bits */
  int newstate = k->keepon &~ (KEEP_RECV_PAUSE| KEEP_SEND_PAUSE);

  /* set the new desired pause bits */
  newstate |= ((action & CURLPAUSE_RECV)?KEEP_RECV_PAUSE:0) |
    ((action & CURLPAUSE_SEND)?KEEP_SEND_PAUSE:0);

  /* put it back in the keepon */
  k->keepon = newstate;

  if(!(newstate & KEEP_RECV_PAUSE) && data->state.tempwrite) {
    /* we have a buffer for sending that we now seem to be able to deliver since
       the receive pausing is lifted! */

    /* get the pointer, type and length in local copies since the function may
       return PAUSE again and then we'll get a new copy allocted and stored in
       the tempwrite variables */
    char *tempwrite = data->state.tempwrite;
    char *freewrite = tempwrite; /* store this pointer to free it later */
    size_t tempsize = data->state.tempwritesize;
    int temptype = data->state.tempwritetype;
    size_t chunklen;

    /* clear tempwrite here just to make sure it gets cleared if there's no
       further use of it, and make sure we don't clear it after the function
       invoke as it may have been set to a new value by then */
    data->state.tempwrite = NULL;

    /* since the write callback API is define to never exceed
       CURL_MAX_WRITE_SIZE bytes in a single call, and since we may in fact
       have more data than that in our buffer here, we must loop sending the
       data in multiple calls until there's no data left or we get another
       pause returned.

       A tricky part is that the function we call will "buffer" the data
       itself when it pauses on a particular buffer, so we may need to do some
       extra trickery if we get a pause return here.
    */
    do {
      chunklen = (tempsize > CURL_MAX_WRITE_SIZE)?CURL_MAX_WRITE_SIZE:tempsize;

      result = Curl_client_write(data->state.current_conn,
                                 temptype, tempwrite, chunklen);
      if(result)
        /* failures abort the loop at once */
        break;

      if(data->state.tempwrite && (tempsize - chunklen)) {
        /* Ouch, the reading is again paused and the block we send is now
           "cached". If this is the final chunk we can leave it like this, but
           if we have more chunks that are cached after this, we need to free
           the newly cached one and put back a version that is truly the entire
           contents that is saved for later
        */
        char *newptr;

        /* note that tempsize is still the size as before the callback was
           used, and thus the whole piece of data to keep */
        newptr = realloc(data->state.tempwrite, tempsize);

        if(!newptr) {
          free(data->state.tempwrite); /* free old area */
          data->state.tempwrite = NULL;
          result = CURLE_OUT_OF_MEMORY;
          /* tempwrite will be freed further down */
          break;
        }
        data->state.tempwrite = newptr; /* store new pointer */
        memcpy(newptr, tempwrite, tempsize);
        data->state.tempwritesize = tempsize; /* store new size */
        /* tempwrite will be freed further down */
        break; /* go back to pausing until further notice */
      }
      else {
        tempsize -= chunklen;  /* left after the call above */
        tempwrite += chunklen; /* advance the pointer */
      }

    } while((result == CURLE_OK) && tempsize);

    free(freewrite); /* this is unconditionally no longer used */
  }

  return result;
}

#ifdef CURL_DOES_CONVERSIONS
/*
 * Curl_convert_to_network() is an internal function
 * for performing ASCII conversions on non-ASCII platforms.
 */
CURLcode Curl_convert_to_network(struct SessionHandle *data,
                                 char *buffer, size_t length)
{
  CURLcode rc;

  if(data->set.convtonetwork) {
    /* use translation callback */
    rc = data->set.convtonetwork(buffer, length);
    if(rc != CURLE_OK) {
      failf(data,
            "CURLOPT_CONV_TO_NETWORK_FUNCTION callback returned %d: %s",
            (int)rc, curl_easy_strerror(rc));
    }
    return(rc);
  }
  else {
#ifdef HAVE_ICONV
    /* do the translation ourselves */
    char *input_ptr, *output_ptr;
    size_t in_bytes, out_bytes, rc;
    int error;

    /* open an iconv conversion descriptor if necessary */
    if(data->outbound_cd == (iconv_t)-1) {
      data->outbound_cd = iconv_open(CURL_ICONV_CODESET_OF_NETWORK,
                                     CURL_ICONV_CODESET_OF_HOST);
      if(data->outbound_cd == (iconv_t)-1) {
        error = ERRNO;
        failf(data,
              "The iconv_open(\"%s\", \"%s\") call failed with errno %i: %s",
               CURL_ICONV_CODESET_OF_NETWORK,
               CURL_ICONV_CODESET_OF_HOST,
               error, strerror(error));
        return CURLE_CONV_FAILED;
      }
    }
    /* call iconv */
    input_ptr = output_ptr = buffer;
    in_bytes = out_bytes = length;
    rc = iconv(data->outbound_cd, (const char**)&input_ptr, &in_bytes,
               &output_ptr, &out_bytes);
    if((rc == ICONV_ERROR) || (in_bytes != 0)) {
      error = ERRNO;
      failf(data,
        "The Curl_convert_to_network iconv call failed with errno %i: %s",
             error, strerror(error));
      return CURLE_CONV_FAILED;
    }
#else
    failf(data, "CURLOPT_CONV_TO_NETWORK_FUNCTION callback required");
    return CURLE_CONV_REQD;
#endif /* HAVE_ICONV */
  }

  return CURLE_OK;
}

/*
 * Curl_convert_from_network() is an internal function
 * for performing ASCII conversions on non-ASCII platforms.
 */
CURLcode Curl_convert_from_network(struct SessionHandle *data,
                                      char *buffer, size_t length)
{
  CURLcode rc;

  if(data->set.convfromnetwork) {
    /* use translation callback */
    rc = data->set.convfromnetwork(buffer, length);
    if(rc != CURLE_OK) {
      failf(data,
            "CURLOPT_CONV_FROM_NETWORK_FUNCTION callback returned %d: %s",
            (int)rc, curl_easy_strerror(rc));
    }
    return(rc);
  }
  else {
#ifdef HAVE_ICONV
    /* do the translation ourselves */
    char *input_ptr, *output_ptr;
    size_t in_bytes, out_bytes, rc;
    int error;

    /* open an iconv conversion descriptor if necessary */
    if(data->inbound_cd == (iconv_t)-1) {
      data->inbound_cd = iconv_open(CURL_ICONV_CODESET_OF_HOST,
                                    CURL_ICONV_CODESET_OF_NETWORK);
      if(data->inbound_cd == (iconv_t)-1) {
        error = ERRNO;
        failf(data,
              "The iconv_open(\"%s\", \"%s\") call failed with errno %i: %s",
              CURL_ICONV_CODESET_OF_HOST,
              CURL_ICONV_CODESET_OF_NETWORK,
              error, strerror(error));
        return CURLE_CONV_FAILED;
      }
    }
    /* call iconv */
    input_ptr = output_ptr = buffer;
    in_bytes = out_bytes = length;
    rc = iconv(data->inbound_cd, (const char **)&input_ptr, &in_bytes,
               &output_ptr, &out_bytes);
    if((rc == ICONV_ERROR) || (in_bytes != 0)) {
      error = ERRNO;
      failf(data,
            "The Curl_convert_from_network iconv call failed with errno %i: %s",
            error, strerror(error));
      return CURLE_CONV_FAILED;
    }
#else
    failf(data, "CURLOPT_CONV_FROM_NETWORK_FUNCTION callback required");
    return CURLE_CONV_REQD;
#endif /* HAVE_ICONV */
  }

  return CURLE_OK;
}

/*
 * Curl_convert_from_utf8() is an internal function
 * for performing UTF-8 conversions on non-ASCII platforms.
 */
CURLcode Curl_convert_from_utf8(struct SessionHandle *data,
                                     char *buffer, size_t length)
{
  CURLcode rc;

  if(data->set.convfromutf8) {
    /* use translation callback */
    rc = data->set.convfromutf8(buffer, length);
    if(rc != CURLE_OK) {
      failf(data,
            "CURLOPT_CONV_FROM_UTF8_FUNCTION callback returned %d: %s",
            (int)rc, curl_easy_strerror(rc));
    }
    return(rc);
  }
  else {
#ifdef HAVE_ICONV
    /* do the translation ourselves */
    const char *input_ptr;
    char *output_ptr;
    size_t in_bytes, out_bytes, rc;
    int error;

    /* open an iconv conversion descriptor if necessary */
    if(data->utf8_cd == (iconv_t)-1) {
      data->utf8_cd = iconv_open(CURL_ICONV_CODESET_OF_HOST,
                                 CURL_ICONV_CODESET_FOR_UTF8);
      if(data->utf8_cd == (iconv_t)-1) {
        error = ERRNO;
        failf(data,
              "The iconv_open(\"%s\", \"%s\") call failed with errno %i: %s",
              CURL_ICONV_CODESET_OF_HOST,
              CURL_ICONV_CODESET_FOR_UTF8,
              error, strerror(error));
        return CURLE_CONV_FAILED;
      }
    }
    /* call iconv */
    input_ptr = output_ptr = buffer;
    in_bytes = out_bytes = length;
    rc = iconv(data->utf8_cd, &input_ptr, &in_bytes,
               &output_ptr, &out_bytes);
    if((rc == ICONV_ERROR) || (in_bytes != 0)) {
      error = ERRNO;
      failf(data,
            "The Curl_convert_from_utf8 iconv call failed with errno %i: %s",
            error, strerror(error));
      return CURLE_CONV_FAILED;
    }
    if(output_ptr < input_ptr) {
      /* null terminate the now shorter output string */
      *output_ptr = 0x00;
    }
#else
    failf(data, "CURLOPT_CONV_FROM_UTF8_FUNCTION callback required");
    return CURLE_CONV_REQD;
#endif /* HAVE_ICONV */
  }

  return CURLE_OK;
}

#endif /* CURL_DOES_CONVERSIONS */

static CURLcode easy_connection(struct SessionHandle *data,
                                curl_socket_t *sfd,
                                struct connectdata **connp)
{
  if(data == NULL)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* only allow these to be called on handles with CURLOPT_CONNECT_ONLY */
  if(!data->set.connect_only) {
    failf(data, "CONNECT_ONLY is required!");
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  *sfd = Curl_getconnectinfo(data, connp);

  if(*sfd == CURL_SOCKET_BAD) {
    failf(data, "Failed to get recent socket");
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  return CURLE_OK;
}

/*
 * Receives data from the connected socket. Use after successful
 * curl_easy_perform() with CURLOPT_CONNECT_ONLY option.
 * Returns CURLE_OK on success, error code on error.
 */
CURLcode curl_easy_recv(CURL *curl, void *buffer, size_t buflen, size_t *n)
{
  curl_socket_t sfd;
  CURLcode ret;
  ssize_t n1;
  struct connectdata *c;
  struct SessionHandle *data = (struct SessionHandle *)curl;

  ret = easy_connection(data, &sfd, &c);
  if(ret)
    return ret;

  *n = 0;
  ret = Curl_read(c, sfd, buffer, buflen, &n1);

  if(ret != CURLE_OK)
    return ret;

  *n = (size_t)n1;

  return CURLE_OK;
}

/*
 * Sends data over the connected socket. Use after successful
 * curl_easy_perform() with CURLOPT_CONNECT_ONLY option.
 */
CURLcode curl_easy_send(CURL *curl, const void *buffer, size_t buflen,
                        size_t *n)
{
  curl_socket_t sfd;
  CURLcode ret;
  ssize_t n1;
  struct connectdata *c = NULL;
  struct SessionHandle *data = (struct SessionHandle *)curl;

  ret = easy_connection(data, &sfd, &c);
  if(ret)
    return ret;

  *n = 0;
  ret = Curl_write(c, sfd, buffer, buflen, &n1);

  if(n1 == -1)
    return CURLE_SEND_ERROR;

  /* detect EAGAIN */
  if((CURLE_OK == ret) && (0 == n1))
    return CURLE_AGAIN;

  *n = (size_t)n1;

  return ret;
}
