#ifndef __SENDF_H
#define __SENDF_H
/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <daniel@haxx.se>
 *
 * 	http://curl.haxx.se
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 ****************************************************************************/

size_t ftpsendf(int fd, struct connectdata *, char *fmt, ...);
size_t sendf(int fd, struct UrlData *, char *fmt, ...);
size_t ssend(int fd, struct connectdata *, void *fmt, size_t len);
void infof(struct UrlData *, char *fmt, ...);
void failf(struct UrlData *, char *fmt, ...);

struct send_buffer {
  char *buffer;
  long size_max;
  long size_used;
};
typedef struct send_buffer send_buffer;


send_buffer *add_buffer_init(void);
CURLcode add_buffer(send_buffer *in, void *inptr, size_t size);
CURLcode add_bufferf(send_buffer *in, char *fmt, ...);
size_t add_buffer_send(int sockfd, struct connectdata *conn, send_buffer *in);


#endif
