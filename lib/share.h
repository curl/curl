#ifndef __CURL_SHARE_H
#define __CURL_SHARE_H

/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

#include "setup.h"
#include <curl/curl.h>

/* this struct is libcurl-private, don't export details */
struct Curl_share {
  unsigned int specifier;
  unsigned int locked;
  unsigned int dirty;
  
  curl_lock_function lockfunc;
  curl_unlock_function unlockfunc;
  void *clientdata;
};

CURLSHcode Curl_share_aquire_lock (struct SessionHandle *, curl_lock_data);
CURLSHcode Curl_share_release_lock (struct SessionHandle *, curl_lock_data);

#endif /* __CURL_SHARE_H */

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
