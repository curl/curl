#ifndef HEADER_CURL_NBD_H
#define HEADER_CURL_NBD_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2018, Richard W.M. Jones, <rjones@redhat.com>
 * Copyright (C) 2018, Red Hat Inc.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#ifndef CURL_DISABLE_NBD

/* The state machine states. */
typedef enum {
  /* The STOP state is used for errors where we cannot continue. */
  NBD_STOP,

  /* After initial connection, wait until the server sends us the
   * greeting containing "NBDMAGIC" string plus version and global
   * flags.
   */
  NBD_EXPECTING_MAGIC,

  /* After receiving magic, send the client flags. */
  NBD_SENDING_CLIENT_FLAGS,

  /* Option negotiation: sending the export name.  NB This must always
   * be the last option.
   */
  NBD_SENDING_EXPORT_NAME,

  /* Expecting data about the export (this finishes the handshake). */
  NBD_EXPECTING_EXPORT_DATA,

  /* Used for some older newstyle servers. */
  NBD_EXPECTING_124_ZEROES,

  /* Connected and idle. */
  NBD_CONNECTED,

  /* Sending a read or write request and expecting the response. */
  NBD_SENDING_REQUEST,
  NBD_EXPECTING_REPLY,
  NBD_DOWNLOADING_DATA,
} nbdstate;

extern const struct Curl_handler Curl_handler_nbd;

/* Per-connection data, accessed through conn->proto. */
struct nbd_conn {
  /* Do not set this directly, use the state() function. */
  nbdstate state;

  char *exportname;             /* Exportname from URL. */

  unsigned short gflags;        /* Global flags from server. */
  curl_off_t size;              /* Export size. */
  unsigned short tflags;        /* Read-only flag and capabilities. */

  /* Receive and send data (only used for NBD messages, not data transfers). */
  char *recv_buf;               /* Receive buffer. */
  size_t received;              /* Bytes received of server message. */
  size_t sent;                  /* Bytes in upload buffer sent. */
  size_t send_size;             /* Total in upload buffer to send. */
  size_t upload_size;           /* Size of following payload (for writes). */
  size_t download_size;         /* Used in DOWNLOADING_DATA state. */
};

#endif

#endif /* HEADER_CURL_NBD_H */
