#ifndef FETCHINC_EASY_H
#define FETCHINC_EASY_H
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
#ifdef  __cplusplus
extern "C" {
#endif

/* Flag bits in the fetch_blob struct: */
#define FETCH_BLOB_COPY   1 /* tell libfetch to copy the data */
#define FETCH_BLOB_NOCOPY 0 /* tell libfetch to NOT copy the data */

struct fetch_blob {
  void *data;
  size_t len;
  unsigned int flags; /* bit 0 is defined, the rest are reserved and should be
                         left zeroes */
};

FETCH_EXTERN FETCH *fetch_easy_init(void);
FETCH_EXTERN FETCHcode fetch_easy_setopt(FETCH *fetch, FETCHoption option, ...);
FETCH_EXTERN FETCHcode fetch_easy_perform(FETCH *fetch);
FETCH_EXTERN void fetch_easy_cleanup(FETCH *fetch);

/*
 * NAME fetch_easy_getinfo()
 *
 * DESCRIPTION
 *
 * Request internal information from the fetch session with this function.
 * The third argument MUST be pointing to the specific type of the used option
 * which is documented in each manpage of the option. The data pointed to
 * will be filled in accordingly and can be relied upon only if the function
 * returns FETCHE_OK. This function is intended to get used *AFTER* a performed
 * transfer, all results from this function are undefined until the transfer
 * is completed.
 */
FETCH_EXTERN FETCHcode fetch_easy_getinfo(FETCH *fetch, FETCHINFO info, ...);


/*
 * NAME fetch_easy_duphandle()
 *
 * DESCRIPTION
 *
 * Creates a new fetch session handle with the same options set for the handle
 * passed in. Duplicating a handle could only be a matter of cloning data and
 * options, internal state info and things like persistent connections cannot
 * be transferred. It is useful in multithreaded applications when you can run
 * fetch_easy_duphandle() for each new thread to avoid a series of identical
 * fetch_easy_setopt() invokes in every thread.
 */
FETCH_EXTERN FETCH *fetch_easy_duphandle(FETCH *fetch);

/*
 * NAME fetch_easy_reset()
 *
 * DESCRIPTION
 *
 * Re-initializes a fetch handle to the default values. This puts back the
 * handle to the same state as it was in when it was just created.
 *
 * It does keep: live connections, the Session ID cache, the DNS cache and the
 * cookies.
 */
FETCH_EXTERN void fetch_easy_reset(FETCH *fetch);

/*
 * NAME fetch_easy_recv()
 *
 * DESCRIPTION
 *
 * Receives data from the connected socket. Use after successful
 * fetch_easy_perform() with FETCHOPT_CONNECT_ONLY option.
 */
FETCH_EXTERN FETCHcode fetch_easy_recv(FETCH *fetch, void *buffer, size_t buflen,
                                    size_t *n);

/*
 * NAME fetch_easy_send()
 *
 * DESCRIPTION
 *
 * Sends data over the connected socket. Use after successful
 * fetch_easy_perform() with FETCHOPT_CONNECT_ONLY option.
 */
FETCH_EXTERN FETCHcode fetch_easy_send(FETCH *fetch, const void *buffer,
                                    size_t buflen, size_t *n);


/*
 * NAME fetch_easy_upkeep()
 *
 * DESCRIPTION
 *
 * Performs connection upkeep for the given session handle.
 */
FETCH_EXTERN FETCHcode fetch_easy_upkeep(FETCH *fetch);

#ifdef  __cplusplus
} /* end of extern "C" */
#endif

#endif
