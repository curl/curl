#ifndef CURL_CONFIG_AMIGAOS_H
#define CURL_CONFIG_AMIGAOS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef __AMIGA__ /* Any AmigaOS flavour */

/* Define to 1 if you want the built-in manual */
#define USE_MANUAL 1

#define OS "AmigaOS"

#define HAVE_CLOSESOCKET_CAMEL  1
#define HAVE_UNISTD_H           1
#define HAVE_STRDUP             1
#define HAVE_UTIME              1
#define HAVE_UTIME_H            1
#define HAVE_SYS_TYPES_H        1
#define HAVE_SYS_SOCKET_H       1
#define HAVE_WRITABLE_ARGV      1
#define HAVE_SYS_TIME_H         1
#define HAVE_TIME_H             1
#define TIME_WITH_SYS_TIME      1
#define HAVE_STRUCT_TIMEVAL     1

#if 0
# define HAVE_TERMIOS_H         1
# define HAVE_FTRUNCATE         1
#endif

#define HAVE_PWD_H              1

#ifndef F_OK
# define F_OK 0
#endif
#ifndef O_RDONLY
# define	O_RDONLY	0x0000		/* open for reading only */
#endif
#ifndef LONG_MAX
# define        LONG_MAX        0x7fffffffL             /* max value for a long */
#endif
#ifndef LONG_MIN
# define        LONG_MIN        (-0x7fffffffL-1)        /* min value for a long */
#endif

#define SIZEOF_INT              4
#define SIZEOF_SHORT            2

#endif /* __AMIGA__ */
#endif /* CURL_CONFIG_AMIGAOS_H */
