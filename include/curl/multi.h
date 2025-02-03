#ifndef FETCHINC_MULTI_H
#define FETCHINC_MULTI_H
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
/*
  This is an "external" header file. Do not give away any internals here!

  GOALS

  o Enable a "pull" interface. The application that uses libfetch decides where
    and when to ask libfetch to get/send data.

  o Enable multiple simultaneous transfers in the same thread without making it
    complicated for the application.

  o Enable the application to select() on its own file descriptors and fetch's
    file descriptors simultaneous easily.

*/

/*
 * This header file should not really need to include "fetch.h" since fetch.h
 * itself includes this file and we expect user applications to do #include
 * <fetch/fetch.h> without the need for especially including multi.h.
 *
 * For some reason we added this include here at one point, and rather than to
 * break existing (wrongly written) libfetch applications, we leave it as-is
 * but with this warning attached.
 */
#include "fetch.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef void FETCHM;

typedef enum {
  FETCHM_CALL_MULTI_PERFORM = -1, /* please call fetch_multi_perform() or
                                    fetch_multi_socket*() soon */
  FETCHM_OK,
  FETCHM_BAD_HANDLE,      /* the passed-in handle is not a valid FETCHM handle */
  FETCHM_BAD_EASY_HANDLE, /* an easy handle was not good/valid */
  FETCHM_OUT_OF_MEMORY,   /* if you ever get this, you are in deep sh*t */
  FETCHM_INTERNAL_ERROR,  /* this is a libfetch bug */
  FETCHM_BAD_SOCKET,      /* the passed in socket argument did not match */
  FETCHM_UNKNOWN_OPTION,  /* fetch_multi_setopt() with unsupported option */
  FETCHM_ADDED_ALREADY,   /* an easy handle already added to a multi handle was
                            attempted to get added - again */
  FETCHM_RECURSIVE_API_CALL, /* an api function was called from inside a
                               callback */
  FETCHM_WAKEUP_FAILURE,  /* wakeup is unavailable or failed */
  FETCHM_BAD_FUNCTION_ARGUMENT, /* function called with a bad parameter */
  FETCHM_ABORTED_BY_CALLBACK,
  FETCHM_UNRECOVERABLE_POLL,
  FETCHM_LAST
} FETCHMcode;

/* just to make code nicer when using fetch_multi_socket() you can now check
   for FETCHM_CALL_MULTI_SOCKET too in the same style it works for
   fetch_multi_perform() and FETCHM_CALL_MULTI_PERFORM */
#define FETCHM_CALL_MULTI_SOCKET FETCHM_CALL_MULTI_PERFORM

/* bitmask bits for FETCHMOPT_PIPELINING */
#define FETCHPIPE_NOTHING   0L
#define FETCHPIPE_HTTP1     1L
#define FETCHPIPE_MULTIPLEX 2L

typedef enum {
  FETCHMSG_NONE, /* first, not used */
  FETCHMSG_DONE, /* This easy handle has completed. 'result' contains
                   the FETCHcode of the transfer */
  FETCHMSG_LAST /* last, not used */
} FETCHMSG;

struct FETCHMsg {
  FETCHMSG msg;       /* what this message means */
  FETCH *easy_handle; /* the handle it concerns */
  union {
    void *whatever;    /* message-specific data */
    FETCHcode result;   /* return code for transfer */
  } data;
};
typedef struct FETCHMsg FETCHMsg;

/* Based on poll(2) structure and values.
 * We do not use pollfd and POLL* constants explicitly
 * to cover platforms without poll(). */
#define FETCH_WAIT_POLLIN    0x0001
#define FETCH_WAIT_POLLPRI   0x0002
#define FETCH_WAIT_POLLOUT   0x0004

struct fetch_waitfd {
  fetch_socket_t fd;
  short events;
  short revents;
};

/*
 * Name:    fetch_multi_init()
 *
 * Desc:    initialize multi-style fetch usage
 *
 * Returns: a new FETCHM handle to use in all 'fetch_multi' functions.
 */
FETCH_EXTERN FETCHM *fetch_multi_init(void);

/*
 * Name:    fetch_multi_add_handle()
 *
 * Desc:    add a standard fetch handle to the multi stack
 *
 * Returns: FETCHMcode type, general multi error code.
 */
FETCH_EXTERN FETCHMcode fetch_multi_add_handle(FETCHM *multi_handle,
                                            FETCH *fetch_handle);

 /*
  * Name:    fetch_multi_remove_handle()
  *
  * Desc:    removes a fetch handle from the multi stack again
  *
  * Returns: FETCHMcode type, general multi error code.
  */
FETCH_EXTERN FETCHMcode fetch_multi_remove_handle(FETCHM *multi_handle,
                                               FETCH *fetch_handle);

 /*
  * Name:    fetch_multi_fdset()
  *
  * Desc:    Ask fetch for its fd_set sets. The app can use these to select() or
  *          poll() on. We want fetch_multi_perform() called as soon as one of
  *          them are ready.
  *
  * Returns: FETCHMcode type, general multi error code.
  */
FETCH_EXTERN FETCHMcode fetch_multi_fdset(FETCHM *multi_handle,
                                       fd_set *read_fd_set,
                                       fd_set *write_fd_set,
                                       fd_set *exc_fd_set,
                                       int *max_fd);

/*
 * Name:     fetch_multi_wait()
 *
 * Desc:     Poll on all fds within a FETCHM set as well as any
 *           additional fds passed to the function.
 *
 * Returns:  FETCHMcode type, general multi error code.
 */
FETCH_EXTERN FETCHMcode fetch_multi_wait(FETCHM *multi_handle,
                                      struct fetch_waitfd extra_fds[],
                                      unsigned int extra_nfds,
                                      int timeout_ms,
                                      int *ret);

/*
 * Name:     fetch_multi_poll()
 *
 * Desc:     Poll on all fds within a FETCHM set as well as any
 *           additional fds passed to the function.
 *
 * Returns:  FETCHMcode type, general multi error code.
 */
FETCH_EXTERN FETCHMcode fetch_multi_poll(FETCHM *multi_handle,
                                      struct fetch_waitfd extra_fds[],
                                      unsigned int extra_nfds,
                                      int timeout_ms,
                                      int *ret);

/*
 * Name:     fetch_multi_wakeup()
 *
 * Desc:     wakes up a sleeping fetch_multi_poll call.
 *
 * Returns:  FETCHMcode type, general multi error code.
 */
FETCH_EXTERN FETCHMcode fetch_multi_wakeup(FETCHM *multi_handle);

 /*
  * Name:    fetch_multi_perform()
  *
  * Desc:    When the app thinks there is data available for fetch it calls this
  *          function to read/write whatever there is right now. This returns
  *          as soon as the reads and writes are done. This function does not
  *          require that there actually is data available for reading or that
  *          data can be written, it can be called just in case. It returns
  *          the number of handles that still transfer data in the second
  *          argument's integer-pointer.
  *
  * Returns: FETCHMcode type, general multi error code. *NOTE* that this only
  *          returns errors etc regarding the whole multi stack. There might
  *          still have occurred problems on individual transfers even when
  *          this returns OK.
  */
FETCH_EXTERN FETCHMcode fetch_multi_perform(FETCHM *multi_handle,
                                         int *running_handles);

 /*
  * Name:    fetch_multi_cleanup()
  *
  * Desc:    Cleans up and removes a whole multi stack. It does not free or
  *          touch any individual easy handles in any way. We need to define
  *          in what state those handles will be if this function is called
  *          in the middle of a transfer.
  *
  * Returns: FETCHMcode type, general multi error code.
  */
FETCH_EXTERN FETCHMcode fetch_multi_cleanup(FETCHM *multi_handle);

/*
 * Name:    fetch_multi_info_read()
 *
 * Desc:    Ask the multi handle if there is any messages/informationals from
 *          the individual transfers. Messages include informationals such as
 *          error code from the transfer or just the fact that a transfer is
 *          completed. More details on these should be written down as well.
 *
 *          Repeated calls to this function will return a new struct each
 *          time, until a special "end of msgs" struct is returned as a signal
 *          that there is no more to get at this point.
 *
 *          The data the returned pointer points to will not survive calling
 *          fetch_multi_cleanup().
 *
 *          The 'FETCHMsg' struct is meant to be simple and only contain basic
 *          information. If more involved information is wanted, we will
 *          provide the particular "transfer handle" in that struct and that
 *          should/could/would be used in subsequent fetch_easy_getinfo() calls
 *          (or similar). The point being that we must never expose complex
 *          structs to applications, as then we will undoubtably get backwards
 *          compatibility problems in the future.
 *
 * Returns: A pointer to a filled-in struct, or NULL if it failed or ran out
 *          of structs. It also writes the number of messages left in the
 *          queue (after this read) in the integer the second argument points
 *          to.
 */
FETCH_EXTERN FETCHMsg *fetch_multi_info_read(FETCHM *multi_handle,
                                          int *msgs_in_queue);

/*
 * Name:    fetch_multi_strerror()
 *
 * Desc:    The fetch_multi_strerror function may be used to turn a FETCHMcode
 *          value into the equivalent human readable error string. This is
 *          useful for printing meaningful error messages.
 *
 * Returns: A pointer to a null-terminated error message.
 */
FETCH_EXTERN const char *fetch_multi_strerror(FETCHMcode);

/*
 * Name:    fetch_multi_socket() and
 *          fetch_multi_socket_all()
 *
 * Desc:    An alternative version of fetch_multi_perform() that allows the
 *          application to pass in one of the file descriptors that have been
 *          detected to have "action" on them and let libfetch perform.
 *          See manpage for details.
 */
#define FETCH_POLL_NONE   0
#define FETCH_POLL_IN     1
#define FETCH_POLL_OUT    2
#define FETCH_POLL_INOUT  3
#define FETCH_POLL_REMOVE 4

#define FETCH_SOCKET_TIMEOUT FETCH_SOCKET_BAD

#define FETCH_CSELECT_IN   0x01
#define FETCH_CSELECT_OUT  0x02
#define FETCH_CSELECT_ERR  0x04

typedef int (*fetch_socket_callback)(FETCH *easy,      /* easy handle */
                                    fetch_socket_t s, /* socket */
                                    int what,        /* see above */
                                    void *userp,     /* private callback
                                                        pointer */
                                    void *socketp);  /* private socket
                                                        pointer */
/*
 * Name:    fetch_multi_timer_callback
 *
 * Desc:    Called by libfetch whenever the library detects a change in the
 *          maximum number of milliseconds the app is allowed to wait before
 *          fetch_multi_socket() or fetch_multi_perform() must be called
 *          (to allow libfetch's timed events to take place).
 *
 * Returns: The callback should return zero.
 */
typedef int (*fetch_multi_timer_callback)(FETCHM *multi,    /* multi handle */
                                         long timeout_ms, /* see above */
                                         void *userp);    /* private callback
                                                             pointer */

FETCH_EXTERN FETCHMcode FETCH_DEPRECATED(7.19.5, "Use fetch_multi_socket_action()")
fetch_multi_socket(FETCHM *multi_handle, fetch_socket_t s, int *running_handles);

FETCH_EXTERN FETCHMcode fetch_multi_socket_action(FETCHM *multi_handle,
                                               fetch_socket_t s,
                                               int ev_bitmask,
                                               int *running_handles);

FETCH_EXTERN FETCHMcode FETCH_DEPRECATED(7.19.5, "Use fetch_multi_socket_action()")
fetch_multi_socket_all(FETCHM *multi_handle, int *running_handles);

#ifndef FETCH_ALLOW_OLD_MULTI_SOCKET
/* This macro below was added in 7.16.3 to push users who recompile to use
   the new fetch_multi_socket_action() instead of the old fetch_multi_socket()
*/
#define fetch_multi_socket(x,y,z) fetch_multi_socket_action(x,y,0,z)
#endif

/*
 * Name:    fetch_multi_timeout()
 *
 * Desc:    Returns the maximum number of milliseconds the app is allowed to
 *          wait before fetch_multi_socket() or fetch_multi_perform() must be
 *          called (to allow libfetch's timed events to take place).
 *
 * Returns: FETCHM error code.
 */
FETCH_EXTERN FETCHMcode fetch_multi_timeout(FETCHM *multi_handle,
                                         long *milliseconds);

typedef enum {
  /* This is the socket callback function pointer */
  FETCHOPT(FETCHMOPT_SOCKETFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 1),

  /* This is the argument passed to the socket callback */
  FETCHOPT(FETCHMOPT_SOCKETDATA, FETCHOPTTYPE_OBJECTPOINT, 2),

    /* set to 1 to enable pipelining for this multi handle */
  FETCHOPT(FETCHMOPT_PIPELINING, FETCHOPTTYPE_LONG, 3),

   /* This is the timer callback function pointer */
  FETCHOPT(FETCHMOPT_TIMERFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 4),

  /* This is the argument passed to the timer callback */
  FETCHOPT(FETCHMOPT_TIMERDATA, FETCHOPTTYPE_OBJECTPOINT, 5),

  /* maximum number of entries in the connection cache */
  FETCHOPT(FETCHMOPT_MAXCONNECTS, FETCHOPTTYPE_LONG, 6),

  /* maximum number of (pipelining) connections to one host */
  FETCHOPT(FETCHMOPT_MAX_HOST_CONNECTIONS, FETCHOPTTYPE_LONG, 7),

  /* maximum number of requests in a pipeline */
  FETCHOPT(FETCHMOPT_MAX_PIPELINE_LENGTH, FETCHOPTTYPE_LONG, 8),

  /* a connection with a content-length longer than this
     will not be considered for pipelining */
  FETCHOPT(FETCHMOPT_CONTENT_LENGTH_PENALTY_SIZE, FETCHOPTTYPE_OFF_T, 9),

  /* a connection with a chunk length longer than this
     will not be considered for pipelining */
  FETCHOPT(FETCHMOPT_CHUNK_LENGTH_PENALTY_SIZE, FETCHOPTTYPE_OFF_T, 10),

  /* a list of site names(+port) that are blocked from pipelining */
  FETCHOPT(FETCHMOPT_PIPELINING_SITE_BL, FETCHOPTTYPE_OBJECTPOINT, 11),

  /* a list of server types that are blocked from pipelining */
  FETCHOPT(FETCHMOPT_PIPELINING_SERVER_BL, FETCHOPTTYPE_OBJECTPOINT, 12),

  /* maximum number of open connections in total */
  FETCHOPT(FETCHMOPT_MAX_TOTAL_CONNECTIONS, FETCHOPTTYPE_LONG, 13),

   /* This is the server push callback function pointer */
  FETCHOPT(FETCHMOPT_PUSHFUNCTION, FETCHOPTTYPE_FUNCTIONPOINT, 14),

  /* This is the argument passed to the server push callback */
  FETCHOPT(FETCHMOPT_PUSHDATA, FETCHOPTTYPE_OBJECTPOINT, 15),

  /* maximum number of concurrent streams to support on a connection */
  FETCHOPT(FETCHMOPT_MAX_CONCURRENT_STREAMS, FETCHOPTTYPE_LONG, 16),

  FETCHMOPT_LASTENTRY /* the last unused */
} FETCHMoption;


/*
 * Name:    fetch_multi_setopt()
 *
 * Desc:    Sets options for the multi handle.
 *
 * Returns: FETCHM error code.
 */
FETCH_EXTERN FETCHMcode fetch_multi_setopt(FETCHM *multi_handle,
                                        FETCHMoption option, ...);


/*
 * Name:    fetch_multi_assign()
 *
 * Desc:    This function sets an association in the multi handle between the
 *          given socket and a private pointer of the application. This is
 *          (only) useful for fetch_multi_socket uses.
 *
 * Returns: FETCHM error code.
 */
FETCH_EXTERN FETCHMcode fetch_multi_assign(FETCHM *multi_handle,
                                        fetch_socket_t sockfd, void *sockp);

/*
 * Name:    fetch_multi_get_handles()
 *
 * Desc:    Returns an allocated array holding all handles currently added to
 *          the multi handle. Marks the final entry with a NULL pointer. If
 *          there is no easy handle added to the multi handle, this function
 *          returns an array with the first entry as a NULL pointer.
 *
 * Returns: NULL on failure, otherwise a FETCH **array pointer
 */
FETCH_EXTERN FETCH **fetch_multi_get_handles(FETCHM *multi_handle);

/*
 * Name: fetch_push_callback
 *
 * Desc: This callback gets called when a new stream is being pushed by the
 *       server. It approves or denies the new stream. It can also decide
 *       to completely fail the connection.
 *
 * Returns: FETCH_PUSH_OK, FETCH_PUSH_DENY or FETCH_PUSH_ERROROUT
 */
#define FETCH_PUSH_OK       0
#define FETCH_PUSH_DENY     1
#define FETCH_PUSH_ERROROUT 2 /* added in 7.72.0 */

struct fetch_pushheaders;  /* forward declaration only */

FETCH_EXTERN char *fetch_pushheader_bynum(struct fetch_pushheaders *h,
                                        size_t num);
FETCH_EXTERN char *fetch_pushheader_byname(struct fetch_pushheaders *h,
                                         const char *name);

typedef int (*fetch_push_callback)(FETCH *parent,
                                  FETCH *easy,
                                  size_t num_headers,
                                  struct fetch_pushheaders *headers,
                                  void *userp);

/*
 * Name:    fetch_multi_waitfds()
 *
 * Desc:    Ask fetch for fds for polling. The app can use these to poll on.
 *          We want fetch_multi_perform() called as soon as one of them are
 *          ready. Passing zero size allows to get just a number of fds.
 *
 * Returns: FETCHMcode type, general multi error code.
 */
FETCH_EXTERN FETCHMcode fetch_multi_waitfds(FETCHM *multi,
                                         struct fetch_waitfd *ufds,
                                         unsigned int size,
                                         unsigned int *fd_count);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif
