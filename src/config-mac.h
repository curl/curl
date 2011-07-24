#ifndef __SRC_CONFIG_MAC_H
#define __SRC_CONFIG_MAC_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* =================================================================== */
/*   src/config-mac.h - Hand crafted config file for Mac OS 9          */
/* =================================================================== */
/*  On Mac OS X you must run configure to generate curl_config.h file  */
/* =================================================================== */

/* Define to 1 if you want the built-in manual */
#define USE_MANUAL 1

#define HAVE_UNISTD_H           1
#define HAVE_ERRNO_H            1
#define HAVE_FCNTL_H            1
#define HAVE_UTIME_H            1
#define HAVE_SYS_UTIME_H        1

#define HAVE_SETVBUF            1
#define HAVE_UTIME              1
#define HAVE_FTRUNCATE          1

#define HAVE_TIME_H             1
#define HAVE_SYS_TIME_H         1
#define TIME_WITH_SYS_TIME      1
#define HAVE_STRUCT_TIMEVAL     1

#define SIZEOF_INT              4
#define SIZEOF_SHORT            2

#define main(x,y) curl_main(x,y)

/* we provide our own strdup prototype */
char *strdup(char *s1);

#endif /* __SRC_CONFIG_MAC_H */
