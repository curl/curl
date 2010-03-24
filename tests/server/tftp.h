#ifndef __SERVER_TFTP_H
#define __SERVER_TFTP_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2008, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* This file is a rewrite/clone of the arpa/tftp.h file for systems without
   it. */

#define SEGSIZE 512 /* data segment size */

#ifndef __GNUC__
#define __attribute__(x)
#endif

/* Using a packed struct as binary in a program is begging for problems, but
   the tftpd server was written like this so we have this struct here to make
   things build. */

struct tftphdr {
  short th_opcode;         /* packet type */
  unsigned short th_block; /* all sorts of things */
  char th_data[1];         /* data or error string */
} __attribute__ ((__packed__));

#define th_stuff th_block
#define th_code  th_block
#define th_msg   th_data

#define EUNDEF    0
#define ENOTFOUND 1
#define EACCESS   2
#define ENOSPACE  3
#define EBADOP    4
#define EBADID    5
#define EEXISTS   6
#define ENOUSER   7

#endif /* __SERVER_TFTP_H */
