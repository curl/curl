#ifndef HEADER_FETCH_URL_H
#define HEADER_FETCH_URL_H
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "fetch_setup.h"

/*
 * Prototypes for library-wide functions provided by url.c
 */

FETCHcode Fetch_init_do(struct Fetch_easy *data, struct connectdata *conn);
FETCHcode Fetch_open(struct Fetch_easy **fetch);
FETCHcode Fetch_init_userdefined(struct Fetch_easy *data);

void Fetch_freeset(struct Fetch_easy *data);
FETCHcode Fetch_uc_to_fetchcode(FETCHUcode uc);
FETCHcode Fetch_close(struct Fetch_easy **datap); /* opposite of fetch_open() */
FETCHcode Fetch_connect(struct Fetch_easy *, bool *async, bool *protocol_connect);
bool Fetch_on_disconnect(struct Fetch_easy *data,
                        struct connectdata *, bool aborted);
FETCHcode Fetch_setup_conn(struct Fetch_easy *data,
                          bool *protocol_done);
void Fetch_conn_free(struct Fetch_easy *data, struct connectdata *conn);
FETCHcode Fetch_parse_login_details(const char *login, const size_t len,
                                   char **userptr, char **passwdptr,
                                   char **optionsptr);

/* Get protocol handler for a URI scheme
 * @param scheme URI scheme, case-insensitive
 * @return NULL of handler not found
 */
const struct Fetch_handler *Fetch_get_scheme_handler(const char *scheme);
const struct Fetch_handler *Fetch_getn_scheme_handler(const char *scheme,
                                                    size_t len);

#define FETCH_DEFAULT_PROXY_PORT 1080      /* default proxy port unless specified */
#define FETCH_DEFAULT_HTTPS_PROXY_PORT 443 /* default https proxy port unless \
                                             specified */

#ifdef FETCH_DISABLE_VERBOSE_STRINGS
#define Fetch_verboseconnect(x, y, z) Fetch_nop_stmt
#else
void Fetch_verboseconnect(struct Fetch_easy *data, struct connectdata *conn,
                         int sockindex);
#endif

/**
 * Return TRUE iff the given connection is considered dead.
 * @param nowp      NULL or pointer to time being checked against.
 */
bool Fetch_conn_seems_dead(struct connectdata *conn,
                          struct Fetch_easy *data,
                          struct fetchtime *nowp);

/**
 * Perform upkeep operations on the connection.
 */
FETCHcode Fetch_conn_upkeep(struct Fetch_easy *data,
                           struct connectdata *conn,
                           struct fetchtime *now);

#if defined(USE_HTTP2) || defined(USE_HTTP3)
void Fetch_data_priority_clear_state(struct Fetch_easy *data);
#else
#define Fetch_data_priority_clear_state(x)
#endif /* !(defined(USE_HTTP2) || defined(USE_HTTP3)) */

#ifdef USE_NGHTTP2
FETCHcode Fetch_data_priority_add_child(struct Fetch_easy *parent,
                                       struct Fetch_easy *child,
                                       bool exclusive);
#else
#define Fetch_data_priority_add_child(x, y, z) FETCHE_NOT_BUILT_IN
#endif

#endif /* HEADER_FETCH_URL_H */
