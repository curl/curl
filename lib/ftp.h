#ifndef __FTP_H
#define __FTP_H
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

#ifndef CURL_DISABLE_FTP
CURLcode Curl_ftp(struct connectdata *conn);
CURLcode Curl_ftp_done(struct connectdata *conn);
CURLcode Curl_ftp_connect(struct connectdata *conn);
CURLcode Curl_ftp_disconnect(struct connectdata *conn);
CURLcode Curl_ftpsendf(struct connectdata *, const char *fmt, ...);
int Curl_GetFTPResponse(char *buf, struct connectdata *conn,
                        int *ftpcode);
CURLcode Curl_ftp_nextconnect(struct connectdata *conn);
#endif

#endif
