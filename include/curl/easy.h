#ifndef CURLINC_EASY_H
#define CURLINC_EASY_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#ifdef  __cplusplus
extern "C" {
#endif

/* Application can use a memory PKCS12 certificate with CURLOPT_SSLCERT
 *  with OpenSSL, Schannel or SecTransport
 *
 *
 *  Example if with certificate binary data and size in:
 *    void* certdata;
 *    size_t certsize;
 *    ...
 *  set the certificate with:
 *    struct curl_blob structblob;
 *    curl_init_blob_dup(&structblob, certdata, certsize);
 *    curl_easy_setopt(curl, CURLOPT_KEYPASSWD, &structblob);
 *             my_setopt_str(curl, CURLOPT_SSLCERT, &structblob);
 *  struct curl_blob is just a 0x20 bytes structures which will
 *  start bt a magic string and contain data
 *
 *  with curl_init_blob_dup, certdata can be discarded after
 *    calling curl_easy_setopt
 *  with curl_init_blob_persist, certdata need be valid when the
 *  connexion is made
 *
 * Note : never call curl_init_blob_xxx without a pointer to a
 *   valid 0x20 bytes block
 * And never use the string CURL_BLOB_MAGIC without a correct
 *   blob block
 *
 *
 * about the idea, see https://curl.haxx.se/mail/lib-2016-09/0074.html */

#define CURL_BLOB_MAGIC          ("\x01" "CurlMemBlob" "\xff\x01")
#define CURL_BLOB_MAGIC_STRLEN   (14)
#define CURL_BLOB_MAGIC_SIZE     (CURL_BLOB_MAGIC_STRLEN + 1)
#define CURL_BLOB_OFFSET_DUPFLAG (CURL_BLOB_MAGIC_SIZE)
#define CURL_BLOB_SIZE_DUPFLAG   (1)
#define CURL_BLOB_OFFSET_DATALEN (CURL_BLOB_OFFSET_DUPFLAG + \
                                  CURL_BLOB_SIZE_DUPFLAG)
#define CURL_BLOB_SIZE_DATALEN   (sizeof(size_t))
#define CURL_BLOB_OFFSET_DATAPTR (CURL_BLOB_OFFSET_DATALEN + \
                                  CURL_BLOB_SIZE_DATALEN)
#define CURL_BLOB_SIZE_DATAPTR   (sizeof(void *))
#define CURL_BLOB_SIZE           (CURL_BLOB_OFFSET_DATAPTR + \
                                  CURL_BLOB_SIZE_DATAPTR)

#define CURL_BLOB_DUPFLAG_COPY   (1)
#define CURL_BLOB_DUPFLAG_NOCOPY (0)

/* the struct curl_blob store binary data parameters
 * the structure size is 0x20 and can be followed by binary data */
struct curl_blob {
  char blob_internal[CURL_BLOB_SIZE];
};


/*
 * Macro WHILE_FALSE may be used to build single-iteration do-while loops,
 * avoiding compiler warnings. Mostly intended for other macro definitions.
 */

#define WHILE_FALSE_EASYCURL  while(0)

#if defined(_MSC_VER) && !defined(__POCC__)
#  undef WHILE_FALSE_EASYCURL
#  if (_MSC_VER < 1500)
#    define WHILE_FALSE_EASYCURL  while(1, 0)
#  else
#    define WHILE_FALSE_EASYCURL \
__pragma(warning(push)) \
__pragma(warning(disable:4127)) \
while(0) \
__pragma(warning(pop))
#  endif
#endif

#define curl_init_blob_flag(structblob, ptr, len, flag) \
  do { \
    char *blob = (structblob)->blob_internal; \
    char *data = (char *)(ptr); \
    size_t size = (size_t)(len); \
    memcpy(blob, CURL_BLOB_MAGIC, CURL_BLOB_MAGIC_SIZE); \
    memcpy(blob + CURL_BLOB_OFFSET_DATALEN, &size, sizeof(size_t)); \
    memcpy(blob + CURL_BLOB_OFFSET_DATAPTR, &data, sizeof(void *)); \
    blob[CURL_BLOB_OFFSET_DUPFLAG] = (char)(flag); \
  } WHILE_FALSE_EASYCURL

#define curl_init_blob_persist(structblob, ptr, len) \
  curl_init_blob_flag((structblob), (ptr), (len), CURL_BLOB_DUPFLAG_NOCOPY)

#define curl_init_blob_dup(structblob, ptr, len) \
  curl_init_blob_flag((structblob), (ptr), (len), CURL_BLOB_DUPFLAG_COPY)



CURL_EXTERN CURL *curl_easy_init(void);
CURL_EXTERN CURLcode curl_easy_setopt(CURL *curl, CURLoption option, ...);
CURL_EXTERN CURLcode curl_easy_perform(CURL *curl);
CURL_EXTERN void curl_easy_cleanup(CURL *curl);

/*
 * NAME curl_easy_getinfo()
 *
 * DESCRIPTION
 *
 * Request internal information from the curl session with this function.  The
 * third argument MUST be a pointer to a long, a pointer to a char * or a
 * pointer to a double (as the documentation describes elsewhere).  The data
 * pointed to will be filled in accordingly and can be relied upon only if the
 * function returns CURLE_OK.  This function is intended to get used *AFTER* a
 * performed transfer, all results from this function are undefined until the
 * transfer is completed.
 */
CURL_EXTERN CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...);


/*
 * NAME curl_easy_duphandle()
 *
 * DESCRIPTION
 *
 * Creates a new curl session handle with the same options set for the handle
 * passed in. Duplicating a handle could only be a matter of cloning data and
 * options, internal state info and things like persistent connections cannot
 * be transferred. It is useful in multithreaded applications when you can run
 * curl_easy_duphandle() for each new thread to avoid a series of identical
 * curl_easy_setopt() invokes in every thread.
 */
CURL_EXTERN CURL *curl_easy_duphandle(CURL *curl);

/*
 * NAME curl_easy_reset()
 *
 * DESCRIPTION
 *
 * Re-initializes a CURL handle to the default values. This puts back the
 * handle to the same state as it was in when it was just created.
 *
 * It does keep: live connections, the Session ID cache, the DNS cache and the
 * cookies.
 */
CURL_EXTERN void curl_easy_reset(CURL *curl);

/*
 * NAME curl_easy_recv()
 *
 * DESCRIPTION
 *
 * Receives data from the connected socket. Use after successful
 * curl_easy_perform() with CURLOPT_CONNECT_ONLY option.
 */
CURL_EXTERN CURLcode curl_easy_recv(CURL *curl, void *buffer, size_t buflen,
                                    size_t *n);

/*
 * NAME curl_easy_send()
 *
 * DESCRIPTION
 *
 * Sends data over the connected socket. Use after successful
 * curl_easy_perform() with CURLOPT_CONNECT_ONLY option.
 */
CURL_EXTERN CURLcode curl_easy_send(CURL *curl, const void *buffer,
                                    size_t buflen, size_t *n);


/*
 * NAME curl_easy_upkeep()
 *
 * DESCRIPTION
 *
 * Performs connection upkeep for the given session handle.
 */
CURL_EXTERN CURLcode curl_easy_upkeep(CURL *curl);

#ifdef  __cplusplus
}
#endif

#endif
