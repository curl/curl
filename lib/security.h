#ifndef __SECURITY_H
#define __SECURITY_H
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

/* this is a re-write */

#include <stdarg.h>
#include "urldata.h"  /* for struct connectdata * */

struct Curl_sec_client_mech {
  const char *name;
  size_t size;
  int (*init)(void *);
  int (*auth)(void *, struct connectdata *);
  void (*end)(void *);
  int (*check_prot)(void *, int);
  int (*overhead)(void *, int, int);
  int (*encode)(void *, void*, int, int, void**, struct connectdata *);
  int (*decode)(void *, void*, int, int, struct connectdata *);
};


#define AUTH_OK		0
#define AUTH_CONTINUE	1
#define AUTH_ERROR	2

extern struct Curl_sec_client_mech Curl_krb4_client_mech;

int Curl_sec_fflush_fd(struct connectdata *conn, int fd);
int Curl_sec_fprintf (struct connectdata *, FILE *, const char *, ...);
int Curl_sec_getc (struct connectdata *conn, FILE *);
int Curl_sec_putc (struct connectdata *conn, int, FILE *);
int Curl_sec_read (struct connectdata *conn, int, void *, int);
int Curl_sec_read_msg (struct connectdata *conn, char *, int);

int Curl_sec_vfprintf(struct connectdata *, FILE *, const char *, va_list);
int Curl_sec_fprintf2(struct connectdata *conn, FILE *f, const char *fmt, ...);
int Curl_sec_vfprintf2(struct connectdata *conn, FILE *, const char *, va_list);
int Curl_sec_write (struct connectdata *conn, int, char *, int);

void Curl_sec_end (struct connectdata *);
int Curl_sec_login (struct connectdata *);
void Curl_sec_prot (int, char **);
int Curl_sec_request_prot (struct connectdata *conn, const char *level);
void Curl_sec_set_protection_level(struct connectdata *conn);
void Curl_sec_status (void);

enum protection_level Curl_set_command_prot(struct connectdata *,
                                            enum protection_level);

#endif
