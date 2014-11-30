/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2014, Bill Nagel <wnagel@tycoint.com>, Exacq Technologies
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

#if !defined(CURL_DISABLE_SMB) && defined(USE_NTLM) && \
    !defined(USE_WINDOWS_SSPI)

#define BUILDING_CURL_SMB_C

#include "smb.h"
#include "urldata.h"
#include "sendf.h"
#include "multiif.h"

/* The last #include file should be: */
#include "memdebug.h"

/* Local API functions */
static CURLcode smb_setup(struct connectdata *conn);
static CURLcode smb_connect(struct connectdata *conn, bool *done);
static CURLcode smb_connection_state(struct connectdata *conn, bool *done);
static CURLcode smb_request_state(struct connectdata *conn, bool *done);
static CURLcode smb_done(struct connectdata *conn, CURLcode status,
                         bool premature);
static CURLcode smb_disconnect(struct connectdata *conn, bool dead);
static int smb_getsock(struct connectdata *conn, curl_socket_t *socks,
                       int numsocks);

/*
 * SMB handler interface
 */
const struct Curl_handler Curl_handler_smb = {
  "SMB",                                /* scheme */
  smb_setup,                            /* setup_connection */
  ZERO_NULL,                            /* do_it */
  smb_done,                             /* done */
  ZERO_NULL,                            /* do_more */
  smb_connect,                          /* connect_it */
  smb_connection_state,                 /* connecting */
  smb_request_state,                    /* doing */
  smb_getsock,                          /* proto_getsock */
  smb_getsock,                          /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  smb_disconnect,                       /* disconnect */
  ZERO_NULL,                            /* readwrite */
  PORT_SMB,                             /* defport */
  CURLPROTO_SMB,                        /* protocol */
  PROTOPT_NONE                          /* flags */
};

#ifdef USE_SSL
/*
 * SMBS handler interface
 */
const struct Curl_handler Curl_handler_smbs = {
  "SMBS",                               /* scheme */
  smb_setup,                            /* setup_connection */
  ZERO_NULL,                            /* do_it */
  smb_done,                             /* done */
  ZERO_NULL,                            /* do_more */
  smb_connect,                          /* connect_it */
  smb_connection_state,                 /* connecting */
  smb_request_state,                    /* doing */
  smb_getsock,                          /* proto_getsock */
  smb_getsock,                          /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  smb_disconnect,                       /* disconnect */
  ZERO_NULL,                            /* readwrite */
  PORT_SMBS,                            /* defport */
  CURLPROTO_SMBS,                       /* protocol */
  PROTOPT_SSL                           /* flags */
};
#endif

static CURLcode smb_setup(struct connectdata *conn)
{
  (void) conn;

  return CURLE_NOT_BUILT_IN;
}

static CURLcode smb_connect(struct connectdata *conn, bool *done)
{
  (void) conn;
  (void) done;

  return CURLE_NOT_BUILT_IN;
}

static CURLcode smb_connection_state(struct connectdata *conn, bool *done)
{
  (void) conn;
  (void) done;

  return CURLE_NOT_BUILT_IN;
}

static CURLcode smb_request_state(struct connectdata *conn, bool *done)
{
  (void) conn;
  (void) done;

  return CURLE_NOT_BUILT_IN;
}

static CURLcode smb_done(struct connectdata *conn, CURLcode status,
                         bool premature)
{
  (void) conn;
  (void) status;
  (void) premature;

  return CURLE_NOT_BUILT_IN;
}

static CURLcode smb_disconnect(struct connectdata *conn, bool dead)
{
  (void) conn;
  (void) dead;

  return CURLE_NOT_BUILT_IN;
}

static int smb_getsock(struct connectdata *conn, curl_socket_t *socks,
                       int numsocks)
{
  (void) conn;
  (void) socks;
  (void) numsocks;

  return GETSOCK_BLANK;
}

#endif /* CURL_DISABLE_SMB && USE_NTLM && USE_WINDOWS_SSPI */
