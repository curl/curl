#ifndef HEADER_CURL_POLARSSLTHREADLOCK_H
#define HEADER_CURL_POLARSSLTHREADLOCK_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010, Hoi-Ho Chan, <hoiho.chan@gmail.com>
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
#include "curl_setup.h"

#ifdef USE_POLARSSL

int polarsslthreadlock_thread_setup(void);
int polarsslthreadlock_thread_cleanup(void);
int polarsslthreadlock_lock_function(int n);
int polarsslthreadlock_unlock_function(int n);

#endif /* USE_POLARSSL */
#endif /* HEADER_CURL_POLARSSLTHREADLOCK_H */
