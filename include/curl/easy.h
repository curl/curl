#ifndef __CURL_EASY_H
#define __CURL_EASY_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2008, Daniel Stenberg, <daniel@haxx.se>, et al.
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

CURL_EXTERN CURL *curl_easy_init(void);
CURL_EXTERN CURLcode curl_easy_setopt(CURL *curl, CURLoption option, ...);
CURL_EXTERN CURLcode curl_easy_setopt_bool(CURL *curl, CURLoption option, int value);
CURL_EXTERN CURLcode curl_easy_setopt_headers(CURL *curl, struct curl_slist *headers);
CURL_EXTERN CURLcode curl_easy_setopt_int(CURL *curl, CURLoption option, long data);
CURL_EXTERN CURLcode curl_easy_setopt_string(CURL *curl, CURLoption option, char *data);
CURL_EXTERN CURLcode curl_easy_setopt_read_function(CURL *curl, void *userData,
                                                    size_t (*read_cb) (char *buffer, size_t size, size_t nitems,
                                                    void *userdata));
CURL_EXTERN CURLcode curl_easy_setopt_write_function(CURL *curl, void *userData,
                                                     size_t (*write_cb) (char *buffer, size_t size, size_t nitems,
                                                     void *userdata));

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
CURL_EXTERN CURLcode curl_easy_getinfo_string(CURL *curl, CURLINFO info, char **data);
CURL_EXTERN CURLcode curl_easy_getinfo_long(CURL *curl, CURLINFO info, long *data);
    
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
CURL_EXTERN CURL* curl_easy_duphandle(CURL *curl);

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

#ifdef  __cplusplus
}
#endif

#endif
