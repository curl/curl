#ifndef __HTTP_NTLM_H
#define __HTTP_NTLM_H
/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2003, Daniel Stenberg, <daniel@haxx.se>, et al.
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

typedef enum {
  CURLNTLM_NONE, /* not a ntlm */
  CURLNTLM_BAD,  /* an ntlm, but one we don't like */
  CURLNTLM_FIRST, /* the first 401-reply we got with NTLM */
  CURLNTLM_FINE, /* an ntlm we act on */

  CURLNTLM_LAST  /* last entry in this enum, don't use */
} CURLntlm;

/* this is for ntlm header input */
CURLntlm Curl_input_ntlm(struct connectdata *conn, char *header);

/* this is for creating ntlm header output */
CURLcode Curl_output_ntlm(struct connectdata *conn);

void Curl_ntlm_cleanup(struct SessionHandle *data);


/* type-1 octet-stream, sent in the first NTLM-authenticated request

byte    protocol[8];     'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
byte    type;            0x01
byte    zero[3];
short   flags;           0xb203
byte    zero[2];

short   dom_len;         domain string length
short   dom_len;         domain string length
short   dom_off;         domain string offset
byte    zero[2];

short   host_len;        host string length
short   host_len;        host string length
short   host_off;        host string offset (always 0x20)
byte    zero[2];

byte    host[*];         host string (ASCII)
byte    dom[*];          domain string (ASCII)

*/

#endif
