#ifndef HEADER_CURL_SERVER_TFTP_H
#define HEADER_CURL_SERVER_TFTP_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "server_setup.h"

/* This file is a rewrite/clone of the arpa/tftp.h file for systems without
   it. */

#define SEGSIZE 512 /* data segment size */

#if defined(__GNUC__) && ((__GNUC__ >= 3) || \
  ((__GNUC__ == 2) && defined(__GNUC_MINOR__) && (__GNUC_MINOR__ >= 7)))
#  define PACKED_STRUCT __attribute__((__packed__))
#else
#  define PACKED_STRUCT /* NOTHING */
#endif

/* Using a packed struct as binary in a program is begging for problems, but
   the tftpd server was written like this so we have this struct here to make
   things build. */

struct tftphdr {
  unsigned short th_opcode; /* packet type */
  unsigned short th_block;  /* all sorts of things */
  char th_data[1];          /* data or error string */
} PACKED_STRUCT;

#define th_stuff th_block
#define th_code  th_block
#define th_msg   th_data

#define TFTP_EUNDEF    0
#define TFTP_ENOTFOUND 1
#define TFTP_EACCESS   2
#define TFTP_ENOSPACE  3
#define TFTP_EBADOP    4
#define TFTP_EBADID    5
#define TFTP_EEXISTS   6
#define TFTP_ENOUSER   7

#endif /* HEADER_CURL_SERVER_TFTP_H */
