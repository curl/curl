#ifndef __CURL_EASY_H
#define __CURL_EASY_H
/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#ifdef  __cplusplus
extern "C" {
#endif

CURL *curl_easy_init(void);
CURLcode curl_easy_setopt(CURL *curl, CURLoption option, ...);
CURLcode curl_easy_perform(CURL *curl);
void curl_easy_cleanup(CURL *curl);

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
CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...);

#ifdef  __cplusplus
}
#endif

#endif
