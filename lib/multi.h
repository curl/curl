#ifndef __CURL_MULTI_H
#define __CURL_MULTI_H
/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2001, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/
/*
  This is meant to be the "external" header file. Don't give away any
  internals here!

  This document presents a mixture of ideas from at least:
  - Daniel Stenberg
  - Steve Dekorte
  - Sterling Hughes
  - Ben Greear

  -------------------------------------------
  GOALS

  o Enable a "pull" interface. The application that uses libcurl decides where
    and when to ask libcurl to get/send data.

  o Enable multiple simultaneous transfers without using threads or making it
    very complicated for the application.

  o Enable the application to select() on its own file descriptors and curl's
    file descriptors simultaneous easily.
  
  Example source using this interface: http://curl.haxx.se/dev/multi-app.c

*/
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <curl/types.h>

typedef void CURLM;

typedef enum {
  CURLM_OK,
  CURLM_BAD_HANDLE,      /* the passed-in handle is not a valid CURLM handle */
  CURLM_BAD_EASY_HANDLE, /* an easy handle was not good/valid */
  CURLM_OUT_OF_MEMORY,   /* if you ever get this, you're in deep sh*t */
  CURLM_LAST
} CURLMcode;

struct CURLMsg {
  CURL *easy_handle;
  void *whatever;
};
typedef struct CURLMsg CURLMsg;

typedef void * CURLMinfo;

/*
 * Desc:    inititalize multi-style curl usage
 * Name:    curl_multi_init()
 * Returns: a new CURLM handle to use in all 'curl_multi' functions.
 */
CURLM *curl_multi_init(void);

/*
 * Desc:    add a standard curl handle to the multi stack
 * Name:    curl_multi_add_handle()
 * Returns: CURLMcode type, general error code.
 */
CURLMcode curl_multi_add_handle(CURLM *multi_handle,
                                CURL *curl_handle);

 /*
  * Desc:    removes a curl handle from the multi stack again
  * Name:    curl_multi_remove_handle()
  * Returns: CURLMcode type, general error code.
  */
CURLMcode curl_multi_remove_handle(CURLM *multi_handle,
                                   CURL *curl_handle);

 /*
  * Desc:    Ask curl for its fd_set sets. The app can use these to select() or
  *          poll() on. We want curl_multi_perform() called as soon as one of
  *          them are ready.
  * Name:    curl_multi_fdset()
  * Returns: CURLMcode type, general error code.
  */
CURLMcode curl_multi_fdset(CURLM *multi_handle,
                           fd_set *read_fd_set, fd_set *write_fd_set,
                           fd_set *exc_fd_set, int *max_fd);

 /*
  * Desc:    When the app thinks there's data available for curl it calls this
  *          function to read/write whatever there is right now. This returns
  *          as soon as the reads and writes are done. This function does not
  *          require that there actually is data available for reading or that
  *          data can be written, it can be called just in case. It returns
  *          the number of handles that still transfer data in the second
  *          argument's integer-pointer.
  * Name:    curl_multi_fdset()
  * Returns: CURLMcode type, general error code. *NOTE* that this only returns
  *          errors etc regardin the whole multi stack. There might still have
  *          occurred problems on invidual transfers even when this returns OK.
  */

CURLMcode curl_multi_perform(CURLM *multi_handle, int *running_handles);

 /*
  * Desc:    Cleans up and removes a whole multi stack.
  * Name:    curl_multi_cleanup()
  * Returns: CURLMcode type, general error code.
  */
CURLMcode curl_multi_cleanup(CURLM *multi_handle);

/* ---------------------------------------------------------------------- */
/*
 * I suggest an fopen style system to get information from the multi layer.
 * I've named these functions "curl_multi_info*" something to make it apparent
 * that they belong together.
 *
 * I expect that the curl_multi_info_open will be used fairly often after
 * calls to curl_multi_perform(), but there's nothing in this design that
 * forces the application to invoke it at that particular time. In fact, many
 * applications will do good without using it at all.  */

/*
 * Desc:    Ask the multi handle if there's any messages/informationals from
 *          the individual transfers. We pass a pointer to a 'CURLMinfo' that
 *          can be used as input in a subsequent call to curl_multi_info_read.
 *
 *          Messages include informationals such as error code from the
 *          transfer or just the fact that a transfer is completed. More
 *          details on these should be written down as well.
 *
 * Name:    curl_multi_info_open()
 * Returns: The number of transfers that have information stored that can be
 *          read. If zero is returned, there's no need to call
 *          curl_multi_info_close() on the returned handle, but there's no
 *          harm in doing so.
 */
int curl_multi_info_open(CURLM *multi_handle, CURLMinfo *info_handle);

/*
 * Desc:    Returns a pointer to a filled-in struct with information.
 *
 *          Repeated calls to this function will return a new struct each
 *          time, until a special "end of msgs" struct is returned as a signal
 *          that there is no more to get at this point.
 *
 *          curl_multi_info_close() should be called when the last info has
 *          been read. In fact, it must be called if curl_multi_info_open()
 *          was called.
 *
 *          The data the returned pointer points to will not survive calling
 *          curl_multi_cleanup().
 *
 *          The 'CURLMsg' struct is meant to be very simple and only contain
 *          very basic informations. If more involved information is wanted,
 *          we will provide the particular "transfer handle" in that struct
 *          and that should/could/would be used in subsequent
 *          curl_easy_getinfo() calls (or similar). The point being that we
 *          must never expose complex structs to applications, as then we'll
 *          undoubtably get backwards compatibility problems in the future.
 *
 * Name:    curl_multi_info_read()
 *
 * Returns: A pointer to a struct, or NULL if it failed or ran out of structs.
 *          Note that if you continue reading until you get a NULL, you did
 *          read at least one too many times!
 */
CURLMsg *curl_multi_info_read(CURLMinfo *info_handle);

/*
 * Desc:    Terminates an info reading "session".
 *
 * Name:    curl_multi_info_close()
 *
 * Returns: When we've read all the info we want from the info_handle, we
 *          signal this to the multi system by calling this function.
 *          After this call, the info_handle can no longer be used.
 *
 */
void curl_multi_info_close(CURLMinfo *info_handle);

#endif
