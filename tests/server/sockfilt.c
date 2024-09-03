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

/* Purpose
 *
 * 1. Accept a TCP connection on a custom port (IPv4 or IPv6), or connect
 *    to a given (localhost) port.
 *
 * 2. Get commands on STDIN. Pass data on to the TCP stream.
 *    Get data from TCP stream and pass on to STDOUT.
 *
 * This program is made to perform all the socket/stream/connection stuff for
 * the test suite's (perl) FTP server. Previously the perl code did all of
 * this by its own, but I decided to let this program do the socket layer
 * because of several things:
 *
 * o We want the perl code to work with rather old perl installations, thus
 *   we cannot use recent perl modules or features.
 *
 * o We want IPv6 support for systems that provide it, and doing optional IPv6
 *   support in perl seems if not impossible so at least awkward.
 *
 * o We want FTP-SSL support, which means that a connection that starts with
 *   plain sockets needs to be able to "go SSL" in the midst. This would also
 *   require some nasty perl stuff I'd rather avoid.
 *
 * (Source originally based on sws.c)
 */

/*
 * Signal handling notes for sockfilt
 * ----------------------------------
 *
 * This program is a single-threaded process.
 *
 * This program is intended to be highly portable and as such it must be kept
 * as simple as possible, due to this the only signal handling mechanisms used
 * will be those of ANSI C, and used only in the most basic form which is good
 * enough for the purpose of this program.
 *
 * For the above reason and the specific needs of this program signals SIGHUP,
 * SIGPIPE and SIGALRM will be simply ignored on systems where this can be
 * done.  If possible, signals SIGINT and SIGTERM will be handled by this
 * program as an indication to cleanup and finish execution as soon as
 * possible.  This will be achieved with a single signal handler
 * 'exit_signal_handler' for both signals.
 *
 * The 'exit_signal_handler' upon the first SIGINT or SIGTERM received signal
 * will just set to one the global var 'got_exit_signal' storing in global var
 * 'exit_signal' the signal that triggered this change.
 *
 * Nothing fancy that could introduce problems is used, the program at certain
 * points in its normal flow checks if var 'got_exit_signal' is set and in
 * case this is true it just makes its way out of loops and functions in
 * structured and well behaved manner to achieve proper program cleanup and
 * termination.
 *
 * Even with the above mechanism implemented it is worthwhile to note that
 * other signals might still be received, or that there might be systems on
 * which it is not possible to trap and ignore some of the above signals.
 * This implies that for increased portability and reliability the program
 * must be coded as if no signal was being ignored or handled at all.  Enjoy
 * it!
 */

#include <signal.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "curlx.h" /* from the private lib dir */
#include "getpart.h"
#include "inet_pton.h"
#include "util.h"
#include "server_sockaddr.h"
#include "timediff.h"
#include "warnless.h"

/* include memdebug.h last */
#include "memdebug.h"

#ifdef USE_WINSOCK
#undef  EINTR
#define EINTR    4 /* errno.h value */
#undef  EAGAIN
#define EAGAIN  11 /* errno.h value */
#undef  ENOMEM
#define ENOMEM  12 /* errno.h value */
#undef  EINVAL
#define EINVAL  22 /* errno.h value */
#endif

#define DEFAULT_PORT 8999

#ifndef DEFAULT_LOGFILE
#define DEFAULT_LOGFILE "log/sockfilt.log"
#endif

/* buffer is this excessively large only to be able to support things like
  test 1003 which tests exceedingly large server response lines */
#define BUFFER_SIZE 17010

const char *serverlogfile = DEFAULT_LOGFILE;

static bool verbose = FALSE;
static bool bind_only = FALSE;
#ifdef USE_IPV6
static bool use_ipv6 = FALSE;
#endif
static const char *ipv_inuse = "IPv4";
static unsigned short port = DEFAULT_PORT;
static unsigned short connectport = 0; /* if non-zero, we activate this mode */

enum sockmode {
  PASSIVE_LISTEN,    /* as a server waiting for connections */
  PASSIVE_CONNECT,   /* as a server, connected to a client */
  ACTIVE,            /* as a client, connected to a server */
  ACTIVE_DISCONNECT  /* as a client, disconnected from server */
};

#if defined(_WIN32) && !defined(CURL_WINDOWS_APP)
/*
 * read-wrapper to support reading from stdin on Windows.
 */
static ssize_t read_wincon(int fd, void *buf, size_t count)
{
  HANDLE handle = NULL;
  DWORD mode, rcount = 0;
  BOOL success;

  if(fd == fileno(stdin)) {
    handle = GetStdHandle(STD_INPUT_HANDLE);
  }
  else {
    return read(fd, buf, count);
  }

  if(GetConsoleMode(handle, &mode)) {
    success = ReadConsole(handle, buf, curlx_uztoul(count), &rcount, NULL);
  }
  else {
    success = ReadFile(handle, buf, curlx_uztoul(count), &rcount, NULL);
  }
  if(success) {
    return rcount;
  }

  errno = (int)GetLastError();
  return -1;
}
#undef  read
#define read(a,b,c) read_wincon(a,b,c)

/*
 * write-wrapper to support writing to stdout and stderr on Windows.
 */
static ssize_t write_wincon(int fd, const void *buf, size_t count)
{
  HANDLE handle = NULL;
  DWORD mode, wcount = 0;
  BOOL success;

  if(fd == fileno(stdout)) {
    handle = GetStdHandle(STD_OUTPUT_HANDLE);
  }
  else if(fd == fileno(stderr)) {
    handle = GetStdHandle(STD_ERROR_HANDLE);
  }
  else {
    return write(fd, buf, count);
  }

  if(GetConsoleMode(handle, &mode)) {
    success = WriteConsole(handle, buf, curlx_uztoul(count), &wcount, NULL);
  }
  else {
    success = WriteFile(handle, buf, curlx_uztoul(count), &wcount, NULL);
  }
  if(success) {
    return wcount;
  }

  errno = (int)GetLastError();
  return -1;
}
#undef  write
#define write(a,b,c) write_wincon(a,b,c)
#endif

/*
 * fullread is a wrapper around the read() function. This will repeat the call
 * to read() until it actually has read the complete number of bytes indicated
 * in nbytes or it fails with a condition that cannot be handled with a simple
 * retry of the read call.
 */

static ssize_t fullread(int filedes, void *buffer, size_t nbytes)
{
  int error;
  ssize_t nread = 0;

  do {
    ssize_t rc = read(filedes,
                      (unsigned char *)buffer + nread, nbytes - nread);

    if(got_exit_signal) {
      logmsg("signalled to die");
      return -1;
    }

    if(rc < 0) {
      error = errno;
      if((error == EINTR) || (error == EAGAIN))
        continue;
      logmsg("reading from file descriptor: %d,", filedes);
      logmsg("unrecoverable read() failure: (%d) %s",
             error, strerror(error));
      return -1;
    }

    if(rc == 0) {
      logmsg("got 0 reading from stdin");
      return 0;
    }

    nread += rc;

  } while((size_t)nread < nbytes);

  if(verbose)
    logmsg("read %zd bytes", nread);

  return nread;
}

/*
 * fullwrite is a wrapper around the write() function. This will repeat the
 * call to write() until it actually has written the complete number of bytes
 * indicated in nbytes or it fails with a condition that cannot be handled
 * with a simple retry of the write call.
 */

static ssize_t fullwrite(int filedes, const void *buffer, size_t nbytes)
{
  int error;
  ssize_t nwrite = 0;

  do {
    ssize_t wc = write(filedes, (const unsigned char *)buffer + nwrite,
                       nbytes - nwrite);

    if(got_exit_signal) {
      logmsg("signalled to die");
      return -1;
    }

    if(wc < 0) {
      error = errno;
      if((error == EINTR) || (error == EAGAIN))
        continue;
      logmsg("writing to file descriptor: %d,", filedes);
      logmsg("unrecoverable write() failure: (%d) %s",
             error, strerror(error));
      return -1;
    }

    if(wc == 0) {
      logmsg("put 0 writing to stdout");
      return 0;
    }

    nwrite += wc;

  } while((size_t)nwrite < nbytes);

  if(verbose)
    logmsg("wrote %zd bytes", nwrite);

  return nwrite;
}

/*
 * read_stdin tries to read from stdin nbytes into the given buffer. This is a
 * blocking function that will only return TRUE when nbytes have actually been
 * read or FALSE when an unrecoverable error has been detected. Failure of this
 * function is an indication that the sockfilt process should terminate.
 */

static bool read_stdin(void *buffer, size_t nbytes)
{
  ssize_t nread = fullread(fileno(stdin), buffer, nbytes);
  if(nread != (ssize_t)nbytes) {
    logmsg("exiting...");
    return FALSE;
  }
  return TRUE;
}

/*
 * write_stdout tries to write to stdio nbytes from the given buffer. This is a
 * blocking function that will only return TRUE when nbytes have actually been
 * written or FALSE when an unrecoverable error has been detected. Failure of
 * this function is an indication that the sockfilt process should terminate.
 */

static bool write_stdout(const void *buffer, size_t nbytes)
{
  ssize_t nwrite = fullwrite(fileno(stdout), buffer, nbytes);
  if(nwrite != (ssize_t)nbytes) {
    logmsg("exiting...");
    return FALSE;
  }
  return TRUE;
}

static void lograw(unsigned char *buffer, ssize_t len)
{
  char data[120];
  ssize_t i;
  unsigned char *ptr = buffer;
  char *optr = data;
  ssize_t width = 0;
  int left = sizeof(data);

  for(i = 0; i<len; i++) {
    switch(ptr[i]) {
    case '\n':
      msnprintf(optr, left, "\\n");
      width += 2;
      optr += 2;
      left -= 2;
      break;
    case '\r':
      msnprintf(optr, left, "\\r");
      width += 2;
      optr += 2;
      left -= 2;
      break;
    default:
      msnprintf(optr, left, "%c", (ISGRAPH(ptr[i]) ||
                                   ptr[i] == 0x20) ?ptr[i]:'.');
      width++;
      optr++;
      left--;
      break;
    }

    if(width>60) {
      logmsg("'%s'", data);
      width = 0;
      optr = data;
      left = sizeof(data);
    }
  }
  if(width)
    logmsg("'%s'", data);
}

/*
 * handle the DATA command
 * maxlen is the available space in buffer (input)
 * *buffer_len is the amount of data in the buffer (output)
 */
static bool read_data_block(unsigned char *buffer, ssize_t maxlen,
    ssize_t *buffer_len)
{
  if(!read_stdin(buffer, 5))
    return FALSE;

  buffer[5] = '\0';

  *buffer_len = (ssize_t)strtol((char *)buffer, NULL, 16);
  if(*buffer_len > maxlen) {
    logmsg("ERROR: Buffer size (%zd bytes) too small for data size "
           "(%zd bytes)", maxlen, *buffer_len);
    return FALSE;
  }
  logmsg("> %zd bytes data, server => client", *buffer_len);

  if(!read_stdin(buffer, *buffer_len))
    return FALSE;

  lograw(buffer, *buffer_len);

  return TRUE;
}


#if defined(USE_WINSOCK) && !defined(CURL_WINDOWS_APP)
/*
 * Winsock select() does not support standard file descriptors,
 * it can only check SOCKETs. The following function is an attempt
 * to re-create a select() function with support for other handle types.
 *
 * select() function with support for Winsock2 sockets and all
 * other handle types supported by WaitForMultipleObjectsEx() as
 * well as disk files, anonymous and names pipes, and character input.
 *
 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms687028.aspx
 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms741572.aspx
 */
struct select_ws_wait_data {
  HANDLE handle; /* actual handle to wait for during select */
  HANDLE signal; /* internal event to signal handle trigger */
  HANDLE abort;  /* internal event to abort waiting threads */
};
#ifdef _WIN32_WCE
static DWORD WINAPI select_ws_wait_thread(LPVOID lpParameter)
#else
#include <process.h>
static unsigned int WINAPI select_ws_wait_thread(void *lpParameter)
#endif
{
  struct select_ws_wait_data *data;
  HANDLE signal, handle, handles[2];
  INPUT_RECORD inputrecord;
  LARGE_INTEGER size, pos;
  DWORD type, length, ret;

  /* retrieve handles from internal structure */
  data = (struct select_ws_wait_data *) lpParameter;
  if(data) {
    handle = data->handle;
    handles[0] = data->abort;
    handles[1] = handle;
    signal = data->signal;
    free(data);
  }
  else
    return (DWORD)-1;

  /* retrieve the type of file to wait on */
  type = GetFileType(handle);
  switch(type) {
    case FILE_TYPE_DISK:
       /* The handle represents a file on disk, this means:
        * - WaitForMultipleObjectsEx will always be signalled for it.
        * - comparison of current position in file and total size of
        *   the file can be used to check if we reached the end yet.
        *
        * Approach: Loop till either the internal event is signalled
        *           or if the end of the file has already been reached.
        */
      while(WaitForMultipleObjectsEx(1, handles, FALSE, 0, FALSE)
            == WAIT_TIMEOUT) {
        /* get total size of file */
        length = 0;
        size.QuadPart = 0;
        size.LowPart = GetFileSize(handle, &length);
        if((size.LowPart != INVALID_FILE_SIZE) ||
            (GetLastError() == NO_ERROR)) {
          size.HighPart = (LONG)length;
          /* get the current position within the file */
          pos.QuadPart = 0;
          pos.LowPart = SetFilePointer(handle, 0, &pos.HighPart, FILE_CURRENT);
          if((pos.LowPart != INVALID_SET_FILE_POINTER) ||
              (GetLastError() == NO_ERROR)) {
            /* compare position with size, abort if not equal */
            if(size.QuadPart == pos.QuadPart) {
              /* sleep and continue waiting */
              SleepEx(0, FALSE);
              continue;
            }
          }
        }
        /* there is some data available, stop waiting */
        logmsg("[select_ws_wait_thread] data available, DISK: %p", handle);
        SetEvent(signal);
      }
      break;

    case FILE_TYPE_CHAR:
       /* The handle represents a character input, this means:
        * - WaitForMultipleObjectsEx will be signalled on any kind of input,
        *   including mouse and window size events we do not care about.
        *
        * Approach: Loop till either the internal event is signalled
        *           or we get signalled for an actual key-event.
        */
      while(WaitForMultipleObjectsEx(2, handles, FALSE, INFINITE, FALSE)
            == WAIT_OBJECT_0 + 1) {
        /* check if this is an actual console handle */
        if(GetConsoleMode(handle, &ret)) {
          /* retrieve an event from the console buffer */
          length = 0;
          if(PeekConsoleInput(handle, &inputrecord, 1, &length)) {
            /* check if the event is not an actual key-event */
            if(length == 1 && inputrecord.EventType != KEY_EVENT) {
              /* purge the non-key-event and continue waiting */
              ReadConsoleInput(handle, &inputrecord, 1, &length);
              continue;
            }
          }
        }
        /* there is some data available, stop waiting */
        logmsg("[select_ws_wait_thread] data available, CHAR: %p", handle);
        SetEvent(signal);
      }
      break;

    case FILE_TYPE_PIPE:
       /* The handle represents an anonymous or named pipe, this means:
        * - WaitForMultipleObjectsEx will always be signalled for it.
        * - peek into the pipe and retrieve the amount of data available.
        *
        * Approach: Loop till either the internal event is signalled
        *           or there is data in the pipe available for reading.
        */
      while(WaitForMultipleObjectsEx(1, handles, FALSE, 0, FALSE)
            == WAIT_TIMEOUT) {
        /* peek into the pipe and retrieve the amount of data available */
        length = 0;
        if(PeekNamedPipe(handle, NULL, 0, NULL, &length, NULL)) {
          /* if there is no data available, sleep and continue waiting */
          if(length == 0) {
            SleepEx(0, FALSE);
            continue;
          }
          else {
            logmsg("[select_ws_wait_thread] PeekNamedPipe len: %lu", length);
          }
        }
        else {
          /* if the pipe has NOT been closed, sleep and continue waiting */
          ret = GetLastError();
          if(ret != ERROR_BROKEN_PIPE) {
            logmsg("[select_ws_wait_thread] PeekNamedPipe error: %lu", ret);
            SleepEx(0, FALSE);
            continue;
          }
          else {
            logmsg("[select_ws_wait_thread] pipe closed, PIPE: %p", handle);
          }
        }
        /* there is some data available, stop waiting */
        logmsg("[select_ws_wait_thread] data available, PIPE: %p", handle);
        SetEvent(signal);
      }
      break;

    default:
      /* The handle has an unknown type, try to wait on it */
      if(WaitForMultipleObjectsEx(2, handles, FALSE, INFINITE, FALSE)
         == WAIT_OBJECT_0 + 1) {
        logmsg("[select_ws_wait_thread] data available, HANDLE: %p", handle);
        SetEvent(signal);
      }
      break;
  }

  return 0;
}
static HANDLE select_ws_wait(HANDLE handle, HANDLE signal, HANDLE abort)
{
#ifdef _WIN32_WCE
  typedef HANDLE curl_win_thread_handle_t;
#else
  typedef uintptr_t curl_win_thread_handle_t;
#endif
  struct select_ws_wait_data *data;
  curl_win_thread_handle_t thread;

  /* allocate internal waiting data structure */
  data = malloc(sizeof(struct select_ws_wait_data));
  if(data) {
    data->handle = handle;
    data->signal = signal;
    data->abort = abort;

    /* launch waiting thread */
#ifdef _WIN32_WCE
    thread = CreateThread(NULL, 0,  &select_ws_wait_thread, data, 0, NULL);
#else
    thread = _beginthreadex(NULL, 0, &select_ws_wait_thread, data, 0, NULL);
#endif

    /* free data if thread failed to launch */
    if(!thread) {
      free(data);
    }
    return (HANDLE)thread;
  }
  return NULL;
}
struct select_ws_data {
  int fd;                /* provided file descriptor  (indexed by nfd) */
  long wsastate;         /* internal pre-select state (indexed by nfd) */
  curl_socket_t wsasock; /* internal socket handle    (indexed by nws) */
  WSAEVENT wsaevent;     /* internal select event     (indexed by nws) */
  HANDLE signal;         /* internal thread signal    (indexed by nth) */
  HANDLE thread;         /* internal thread handle    (indexed by nth) */
};
static int select_ws(int nfds, fd_set *readfds, fd_set *writefds,
                     fd_set *exceptfds, struct timeval *tv)
{
  DWORD timeout_ms, wait, nfd, nth, nws, i;
  HANDLE abort, signal, handle, *handles;
  fd_set readsock, writesock, exceptsock;
  struct select_ws_data *data;
  WSANETWORKEVENTS wsaevents;
  curl_socket_t wsasock;
  int error, ret, fd;
  WSAEVENT wsaevent;

  /* check if the input value is valid */
  if(nfds < 0) {
    errno = EINVAL;
    return -1;
  }

  /* convert struct timeval to milliseconds */
  if(tv) {
    timeout_ms = (DWORD)curlx_tvtoms(tv);
  }
  else {
    timeout_ms = INFINITE;
  }

  /* check if we got descriptors, sleep in case we got none */
  if(!nfds) {
    SleepEx(timeout_ms, FALSE);
    return 0;
  }

  /* create internal event to abort waiting threads */
  abort = CreateEvent(NULL, TRUE, FALSE, NULL);
  if(!abort) {
    errno = ENOMEM;
    return -1;
  }

  /* allocate internal array for the internal data */
  data = calloc(nfds, sizeof(struct select_ws_data));
  if(!data) {
    CloseHandle(abort);
    errno = ENOMEM;
    return -1;
  }

  /* allocate internal array for the internal event handles */
  handles = calloc(nfds + 1, sizeof(HANDLE));
  if(!handles) {
    CloseHandle(abort);
    free(data);
    errno = ENOMEM;
    return -1;
  }

  /* loop over the handles in the input descriptor sets */
  nfd = 0; /* number of handled file descriptors */
  nth = 0; /* number of internal waiting threads */
  nws = 0; /* number of handled Winsock sockets */
  for(fd = 0; fd < nfds; fd++) {
    wsasock = curlx_sitosk(fd);
    wsaevents.lNetworkEvents = 0;
    handles[nfd] = 0;

    FD_ZERO(&readsock);
    FD_ZERO(&writesock);
    FD_ZERO(&exceptsock);

    if(FD_ISSET(wsasock, readfds)) {
      FD_SET(wsasock, &readsock);
      wsaevents.lNetworkEvents |= FD_READ|FD_ACCEPT|FD_CLOSE;
    }

    if(FD_ISSET(wsasock, writefds)) {
      FD_SET(wsasock, &writesock);
      wsaevents.lNetworkEvents |= FD_WRITE|FD_CONNECT|FD_CLOSE;
    }

    if(FD_ISSET(wsasock, exceptfds)) {
      FD_SET(wsasock, &exceptsock);
      wsaevents.lNetworkEvents |= FD_OOB;
    }

    /* only wait for events for which we actually care */
    if(wsaevents.lNetworkEvents) {
      data[nfd].fd = fd;
      if(fd == fileno(stdin)) {
        signal = CreateEvent(NULL, TRUE, FALSE, NULL);
        if(signal) {
          handle = GetStdHandle(STD_INPUT_HANDLE);
          handle = select_ws_wait(handle, signal, abort);
          if(handle) {
            handles[nfd] = signal;
            data[nth].signal = signal;
            data[nth].thread = handle;
            nfd++;
            nth++;
          }
          else {
            CloseHandle(signal);
          }
        }
      }
      else if(fd == fileno(stdout)) {
        handles[nfd] = GetStdHandle(STD_OUTPUT_HANDLE);
        nfd++;
      }
      else if(fd == fileno(stderr)) {
        handles[nfd] = GetStdHandle(STD_ERROR_HANDLE);
        nfd++;
      }
      else {
        wsaevent = WSACreateEvent();
        if(wsaevent != WSA_INVALID_EVENT) {
          if(wsaevents.lNetworkEvents & FD_WRITE) {
            send(wsasock, NULL, 0, 0); /* reset FD_WRITE */
          }
          error = WSAEventSelect(wsasock, wsaevent, wsaevents.lNetworkEvents);
          if(error != SOCKET_ERROR) {
            handles[nfd] = (HANDLE)wsaevent;
            data[nws].wsasock = wsasock;
            data[nws].wsaevent = wsaevent;
            data[nfd].wsastate = 0;
            tv->tv_sec = 0;
            tv->tv_usec = 0;
            /* check if the socket is already ready */
            if(select(fd + 1, &readsock, &writesock, &exceptsock, tv) == 1) {
              logmsg("[select_ws] socket %d is ready", fd);
              WSASetEvent(wsaevent);
              if(FD_ISSET(wsasock, &readsock))
                data[nfd].wsastate |= FD_READ;
              if(FD_ISSET(wsasock, &writesock))
                data[nfd].wsastate |= FD_WRITE;
              if(FD_ISSET(wsasock, &exceptsock))
                data[nfd].wsastate |= FD_OOB;
            }
            nfd++;
            nws++;
          }
          else {
            WSACloseEvent(wsaevent);
            signal = CreateEvent(NULL, TRUE, FALSE, NULL);
            if(signal) {
              handle = (HANDLE)wsasock;
              handle = select_ws_wait(handle, signal, abort);
              if(handle) {
                handles[nfd] = signal;
                data[nth].signal = signal;
                data[nth].thread = handle;
                nfd++;
                nth++;
              }
              else {
                CloseHandle(signal);
              }
            }
          }
        }
      }
    }
  }

  /* wait on the number of handles */
  wait = nfd;

  /* make sure we stop waiting on exit signal event */
  if(exit_event) {
    /* we allocated handles nfds + 1 for this */
    handles[nfd] = exit_event;
    wait += 1;
  }

  /* wait for one of the internal handles to trigger */
  wait = WaitForMultipleObjectsEx(wait, handles, FALSE, timeout_ms, FALSE);

  /* signal the abort event handle and join the other waiting threads */
  SetEvent(abort);
  for(i = 0; i < nth; i++) {
    WaitForSingleObjectEx(data[i].thread, INFINITE, FALSE);
    CloseHandle(data[i].thread);
  }

  /* loop over the internal handles returned in the descriptors */
  ret = 0; /* number of ready file descriptors */
  for(i = 0; i < nfd; i++) {
    fd = data[i].fd;
    handle = handles[i];
    wsasock = curlx_sitosk(fd);

    /* check if the current internal handle was triggered */
    if(wait != WAIT_FAILED && (wait - WAIT_OBJECT_0) <= i &&
       WaitForSingleObjectEx(handle, 0, FALSE) == WAIT_OBJECT_0) {
      /* first handle stdin, stdout and stderr */
      if(fd == fileno(stdin)) {
        /* stdin is never ready for write or exceptional */
        FD_CLR(wsasock, writefds);
        FD_CLR(wsasock, exceptfds);
      }
      else if(fd == fileno(stdout) || fd == fileno(stderr)) {
        /* stdout and stderr are never ready for read or exceptional */
        FD_CLR(wsasock, readfds);
        FD_CLR(wsasock, exceptfds);
      }
      else {
        /* try to handle the event with the Winsock2 functions */
        wsaevents.lNetworkEvents = 0;
        error = WSAEnumNetworkEvents(wsasock, handle, &wsaevents);
        if(error != SOCKET_ERROR) {
          /* merge result from pre-check using select */
          wsaevents.lNetworkEvents |= data[i].wsastate;

          /* remove from descriptor set if not ready for read/accept/close */
          if(!(wsaevents.lNetworkEvents & (FD_READ|FD_ACCEPT|FD_CLOSE)))
            FD_CLR(wsasock, readfds);

          /* remove from descriptor set if not ready for write/connect */
          if(!(wsaevents.lNetworkEvents & (FD_WRITE|FD_CONNECT|FD_CLOSE)))
            FD_CLR(wsasock, writefds);

          /* remove from descriptor set if not exceptional */
          if(!(wsaevents.lNetworkEvents & FD_OOB))
            FD_CLR(wsasock, exceptfds);
        }
      }

      /* check if the event has not been filtered using specific tests */
      if(FD_ISSET(wsasock, readfds) || FD_ISSET(wsasock, writefds) ||
         FD_ISSET(wsasock, exceptfds)) {
        ret++;
      }
    }
    else {
      /* remove from all descriptor sets since this handle did not trigger */
      FD_CLR(wsasock, readfds);
      FD_CLR(wsasock, writefds);
      FD_CLR(wsasock, exceptfds);
    }
  }

  for(fd = 0; fd < nfds; fd++) {
    if(FD_ISSET(fd, readfds))
      logmsg("[select_ws] %d is readable", fd);
    if(FD_ISSET(fd, writefds))
      logmsg("[select_ws] %d is writable", fd);
    if(FD_ISSET(fd, exceptfds))
      logmsg("[select_ws] %d is exceptional", fd);
  }

  for(i = 0; i < nws; i++) {
    WSAEventSelect(data[i].wsasock, NULL, 0);
    WSACloseEvent(data[i].wsaevent);
  }

  for(i = 0; i < nth; i++) {
    CloseHandle(data[i].signal);
  }
  CloseHandle(abort);

  free(handles);
  free(data);

  return ret;
}
#define select(a,b,c,d,e) select_ws(a,b,c,d,e)
#endif  /* USE_WINSOCK */


/* Perform the disconnect handshake with sockfilt
 * This involves waiting for the disconnect acknowledgment after the DISC
 * command, while throwing away anything else that might come in before
 * that.
 */
static bool disc_handshake(void)
{
  if(!write_stdout("DISC\n", 5))
    return FALSE;

  do {
      unsigned char buffer[BUFFER_SIZE];
      ssize_t buffer_len;
      if(!read_stdin(buffer, 5))
        return FALSE;
      logmsg("Received %c%c%c%c (on stdin)",
             buffer[0], buffer[1], buffer[2], buffer[3]);

      if(!memcmp("ACKD", buffer, 4)) {
        /* got the ack we were waiting for */
        break;
      }
      else if(!memcmp("DISC", buffer, 4)) {
        logmsg("Crikey! Client also wants to disconnect");
        if(!write_stdout("ACKD\n", 5))
          return FALSE;
      }
      else if(!memcmp("DATA", buffer, 4)) {
        /* We must read more data to stay in sync */
        logmsg("Throwing away data bytes");
        if(!read_data_block(buffer, sizeof(buffer), &buffer_len))
          return FALSE;

      }
      else if(!memcmp("QUIT", buffer, 4)) {
        /* just die */
        logmsg("quits");
        return FALSE;
      }
      else {
        logmsg("Error: unexpected message; aborting");
        /*
         * The only other messages that could occur here are PING and PORT,
         * and both of them occur at the start of a test when nothing should be
         * trying to DISC. Therefore, we should not ever get here, but if we
         * do, it's probably due to some kind of unclean shutdown situation so
         * us shutting down is what we probably ought to be doing, anyway.
         */
        return FALSE;
      }

  } while(TRUE);
  return TRUE;
}

/*
  sockfdp is a pointer to an established stream or CURL_SOCKET_BAD

  if sockfd is CURL_SOCKET_BAD, listendfd is a listening socket we must
  accept()
*/
static bool juggle(curl_socket_t *sockfdp,
                   curl_socket_t listenfd,
                   enum sockmode *mode)
{
  struct timeval timeout;
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_err;
  curl_socket_t sockfd = CURL_SOCKET_BAD;
  int maxfd = -99;
  ssize_t rc;
  int error = 0;

  unsigned char buffer[BUFFER_SIZE];
  char data[16];

  if(got_exit_signal) {
    logmsg("signalled to die, exiting...");
    return FALSE;
  }

#ifdef HAVE_GETPPID
  /* As a last resort, quit if sockfilt process becomes orphan. Just in case
     parent ftpserver process has died without killing its sockfilt children */
  if(getppid() <= 1) {
    logmsg("process becomes orphan, exiting");
    return FALSE;
  }
#endif

  timeout.tv_sec = 120;
  timeout.tv_usec = 0;

  FD_ZERO(&fds_read);
  FD_ZERO(&fds_write);
  FD_ZERO(&fds_err);

  FD_SET((curl_socket_t)fileno(stdin), &fds_read);

  switch(*mode) {

  case PASSIVE_LISTEN:

    /* server mode */
    sockfd = listenfd;
    /* there's always a socket to wait for */
    FD_SET(sockfd, &fds_read);
    maxfd = (int)sockfd;
    break;

  case PASSIVE_CONNECT:

    sockfd = *sockfdp;
    if(CURL_SOCKET_BAD == sockfd) {
      /* eeek, we are supposedly connected and then this cannot be -1 ! */
      logmsg("socket is -1! on %s:%d", __FILE__, __LINE__);
      maxfd = 0; /* stdin */
    }
    else {
      /* there's always a socket to wait for */
      FD_SET(sockfd, &fds_read);
      maxfd = (int)sockfd;
    }
    break;

  case ACTIVE:

    sockfd = *sockfdp;
    /* sockfd turns CURL_SOCKET_BAD when our connection has been closed */
    if(CURL_SOCKET_BAD != sockfd) {
      FD_SET(sockfd, &fds_read);
      maxfd = (int)sockfd;
    }
    else {
      logmsg("No socket to read on");
      maxfd = 0;
    }
    break;

  case ACTIVE_DISCONNECT:

    logmsg("disconnected, no socket to read on");
    maxfd = 0;
    sockfd = CURL_SOCKET_BAD;
    break;

  } /* switch(*mode) */


  do {

    /* select() blocking behavior call on blocking descriptors please */

    rc = select(maxfd + 1, &fds_read, &fds_write, &fds_err, &timeout);

    if(got_exit_signal) {
      logmsg("signalled to die, exiting...");
      return FALSE;
    }

  } while((rc == -1) && ((error = errno) == EINTR));

  if(rc < 0) {
    logmsg("select() failed with error: (%d) %s",
           error, strerror(error));
    return FALSE;
  }

  if(rc == 0)
    /* timeout */
    return TRUE;


  if(FD_ISSET(fileno(stdin), &fds_read)) {
    ssize_t buffer_len;
    /* read from stdin, commands/data to be dealt with and possibly passed on
       to the socket

       protocol:

       4 letter command + LF [mandatory]

       4-digit hexadecimal data length + LF [if the command takes data]
       data                       [the data being as long as set above]

       Commands:

       DATA - plain pass-through data
    */

    if(!read_stdin(buffer, 5))
      return FALSE;

    logmsg("Received %c%c%c%c (on stdin)",
           buffer[0], buffer[1], buffer[2], buffer[3]);

    if(!memcmp("PING", buffer, 4)) {
      /* send reply on stdout, just proving we are alive */
      if(!write_stdout("PONG\n", 5))
        return FALSE;
    }

    else if(!memcmp("PORT", buffer, 4)) {
      /* Question asking us what PORT number we are listening to.
         Replies to PORT with "IPv[num]/[port]" */
      msnprintf((char *)buffer, sizeof(buffer), "%s/%hu\n", ipv_inuse, port);
      buffer_len = (ssize_t)strlen((char *)buffer);
      msnprintf(data, sizeof(data), "PORT\n%04zx\n", buffer_len);
      if(!write_stdout(data, 10))
        return FALSE;
      if(!write_stdout(buffer, buffer_len))
        return FALSE;
    }
    else if(!memcmp("QUIT", buffer, 4)) {
      /* just die */
      logmsg("quits");
      return FALSE;
    }
    else if(!memcmp("DATA", buffer, 4)) {
      /* data IN => data OUT */
      if(!read_data_block(buffer, sizeof(buffer), &buffer_len))
        return FALSE;

      if(*mode == PASSIVE_LISTEN) {
        logmsg("*** We are disconnected!");
        if(!disc_handshake())
          return FALSE;
      }
      else {
        /* send away on the socket */
        ssize_t bytes_written = swrite(sockfd, buffer, buffer_len);
        if(bytes_written != buffer_len) {
          logmsg("Not all data was sent. Bytes to send: %zd sent: %zd",
                 buffer_len, bytes_written);
        }
      }
    }
    else if(!memcmp("DISC", buffer, 4)) {
      /* disconnect! */
      if(!write_stdout("ACKD\n", 5))
        return FALSE;
      if(sockfd != CURL_SOCKET_BAD) {
        logmsg("====> Client forcibly disconnected");
        sclose(sockfd);
        *sockfdp = CURL_SOCKET_BAD;
        if(*mode == PASSIVE_CONNECT)
          *mode = PASSIVE_LISTEN;
        else
          *mode = ACTIVE_DISCONNECT;
      }
      else
        logmsg("attempt to close already dead connection");
      return TRUE;
    }
  }


  if((sockfd != CURL_SOCKET_BAD) && (FD_ISSET(sockfd, &fds_read)) ) {
    ssize_t nread_socket;
    if(*mode == PASSIVE_LISTEN) {
      /* there's no stream set up yet, this is an indication that there's a
         client connecting. */
      curl_socket_t newfd = accept(sockfd, NULL, NULL);
      if(CURL_SOCKET_BAD == newfd) {
        error = SOCKERRNO;
        logmsg("accept(%" FMT_SOCKET_T ", NULL, NULL) "
               "failed with error: (%d) %s", sockfd, error, sstrerror(error));
      }
      else {
        logmsg("====> Client connect");
        if(!write_stdout("CNCT\n", 5))
          return FALSE;
        *sockfdp = newfd; /* store the new socket */
        *mode = PASSIVE_CONNECT; /* we have connected */
      }
      return TRUE;
    }

    /* read from socket, pass on data to stdout */
    nread_socket = sread(sockfd, buffer, sizeof(buffer));

    if(nread_socket > 0) {
      msnprintf(data, sizeof(data), "DATA\n%04zx\n", nread_socket);
      if(!write_stdout(data, 10))
        return FALSE;
      if(!write_stdout(buffer, nread_socket))
        return FALSE;

      logmsg("< %zd bytes data, client => server", nread_socket);
      lograw(buffer, nread_socket);
    }

    if(nread_socket <= 0) {
      logmsg("====> Client disconnect");
      if(!disc_handshake())
        return FALSE;
      sclose(sockfd);
      *sockfdp = CURL_SOCKET_BAD;
      if(*mode == PASSIVE_CONNECT)
        *mode = PASSIVE_LISTEN;
      else
        *mode = ACTIVE_DISCONNECT;
      return TRUE;
    }
  }

  return TRUE;
}

static curl_socket_t sockdaemon(curl_socket_t sock,
                                unsigned short *listenport)
{
  /* passive daemon style */
  srvr_sockaddr_union_t listener;
  int flag;
  int rc;
  int totdelay = 0;
  int maxretr = 10;
  int delay = 20;
  int attempt = 0;
  int error = 0;

  do {
    attempt++;
    flag = 1;
    rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
         (void *)&flag, sizeof(flag));
    if(rc) {
      error = SOCKERRNO;
      logmsg("setsockopt(SO_REUSEADDR) failed with error: (%d) %s",
             error, sstrerror(error));
      if(maxretr) {
        rc = wait_ms(delay);
        if(rc) {
          /* should not happen */
          error = errno;
          logmsg("wait_ms() failed with error: (%d) %s",
                 error, strerror(error));
          sclose(sock);
          return CURL_SOCKET_BAD;
        }
        if(got_exit_signal) {
          logmsg("signalled to die, exiting...");
          sclose(sock);
          return CURL_SOCKET_BAD;
        }
        totdelay += delay;
        delay *= 2; /* double the sleep for next attempt */
      }
    }
  } while(rc && maxretr--);

  if(rc) {
    logmsg("setsockopt(SO_REUSEADDR) failed %d times in %d ms. Error: (%d) %s",
           attempt, totdelay, error, strerror(error));
    logmsg("Continuing anyway...");
  }

  /* When the specified listener port is zero, it is actually a
     request to let the system choose a non-zero available port. */

#ifdef USE_IPV6
  if(!use_ipv6) {
#endif
    memset(&listener.sa4, 0, sizeof(listener.sa4));
    listener.sa4.sin_family = AF_INET;
    listener.sa4.sin_addr.s_addr = INADDR_ANY;
    listener.sa4.sin_port = htons(*listenport);
    rc = bind(sock, &listener.sa, sizeof(listener.sa4));
#ifdef USE_IPV6
  }
  else {
    memset(&listener.sa6, 0, sizeof(listener.sa6));
    listener.sa6.sin6_family = AF_INET6;
    listener.sa6.sin6_addr = in6addr_any;
    listener.sa6.sin6_port = htons(*listenport);
    rc = bind(sock, &listener.sa, sizeof(listener.sa6));
  }
#endif /* USE_IPV6 */
  if(rc) {
    error = SOCKERRNO;
    logmsg("Error binding socket on port %hu: (%d) %s",
           *listenport, error, sstrerror(error));
    sclose(sock);
    return CURL_SOCKET_BAD;
  }

  if(!*listenport) {
    /* The system was supposed to choose a port number, figure out which
       port we actually got and update the listener port value with it. */
    curl_socklen_t la_size;
    srvr_sockaddr_union_t localaddr;
#ifdef USE_IPV6
    if(!use_ipv6)
#endif
      la_size = sizeof(localaddr.sa4);
#ifdef USE_IPV6
    else
      la_size = sizeof(localaddr.sa6);
#endif
    memset(&localaddr.sa, 0, (size_t)la_size);
    if(getsockname(sock, &localaddr.sa, &la_size) < 0) {
      error = SOCKERRNO;
      logmsg("getsockname() failed with error: (%d) %s",
             error, sstrerror(error));
      sclose(sock);
      return CURL_SOCKET_BAD;
    }
    switch(localaddr.sa.sa_family) {
    case AF_INET:
      *listenport = ntohs(localaddr.sa4.sin_port);
      break;
#ifdef USE_IPV6
    case AF_INET6:
      *listenport = ntohs(localaddr.sa6.sin6_port);
      break;
#endif
    default:
      break;
    }
    if(!*listenport) {
      /* Real failure, listener port shall not be zero beyond this point. */
      logmsg("Apparently getsockname() succeeded, with listener port zero.");
      logmsg("A valid reason for this failure is a binary built without");
      logmsg("proper network library linkage. This might not be the only");
      logmsg("reason, but double check it before anything else.");
      sclose(sock);
      return CURL_SOCKET_BAD;
    }
  }

  /* bindonly option forces no listening */
  if(bind_only) {
    logmsg("instructed to bind port without listening");
    return sock;
  }

  /* start accepting connections */
  rc = listen(sock, 5);
  if(0 != rc) {
    error = SOCKERRNO;
    logmsg("listen(%" FMT_SOCKET_T ", 5) failed with error: (%d) %s",
           sock, error, sstrerror(error));
    sclose(sock);
    return CURL_SOCKET_BAD;
  }

  return sock;
}


int main(int argc, char *argv[])
{
  srvr_sockaddr_union_t me;
  curl_socket_t sock = CURL_SOCKET_BAD;
  curl_socket_t msgsock = CURL_SOCKET_BAD;
  int wrotepidfile = 0;
  int wroteportfile = 0;
  const char *pidname = ".sockfilt.pid";
  const char *portname = NULL; /* none by default */
  bool juggle_again;
  int rc;
  int error;
  int arg = 1;
  enum sockmode mode = PASSIVE_LISTEN; /* default */
  const char *addr = NULL;

  while(argc>arg) {
    if(!strcmp("--version", argv[arg])) {
      printf("sockfilt IPv4%s\n",
#ifdef USE_IPV6
             "/IPv6"
#else
             ""
#endif
             );
      return 0;
    }
    else if(!strcmp("--verbose", argv[arg])) {
      verbose = TRUE;
      arg++;
    }
    else if(!strcmp("--pidfile", argv[arg])) {
      arg++;
      if(argc>arg)
        pidname = argv[arg++];
    }
    else if(!strcmp("--portfile", argv[arg])) {
      arg++;
      if(argc > arg)
        portname = argv[arg++];
    }
    else if(!strcmp("--logfile", argv[arg])) {
      arg++;
      if(argc>arg)
        serverlogfile = argv[arg++];
    }
    else if(!strcmp("--ipv6", argv[arg])) {
#ifdef USE_IPV6
      ipv_inuse = "IPv6";
      use_ipv6 = TRUE;
#endif
      arg++;
    }
    else if(!strcmp("--ipv4", argv[arg])) {
      /* for completeness, we support this option as well */
#ifdef USE_IPV6
      ipv_inuse = "IPv4";
      use_ipv6 = FALSE;
#endif
      arg++;
    }
    else if(!strcmp("--bindonly", argv[arg])) {
      bind_only = TRUE;
      arg++;
    }
    else if(!strcmp("--port", argv[arg])) {
      arg++;
      if(argc>arg) {
        char *endptr;
        unsigned long ulnum = strtoul(argv[arg], &endptr, 10);
        port = curlx_ultous(ulnum);
        arg++;
      }
    }
    else if(!strcmp("--connect", argv[arg])) {
      /* Asked to actively connect to the specified local port instead of
         doing a passive server-style listening. */
      arg++;
      if(argc>arg) {
        char *endptr;
        unsigned long ulnum = strtoul(argv[arg], &endptr, 10);
        if((endptr != argv[arg] + strlen(argv[arg])) ||
           (ulnum < 1025UL) || (ulnum > 65535UL)) {
          fprintf(stderr, "sockfilt: invalid --connect argument (%s)\n",
                  argv[arg]);
          return 0;
        }
        connectport = curlx_ultous(ulnum);
        arg++;
      }
    }
    else if(!strcmp("--addr", argv[arg])) {
      /* Set an IP address to use with --connect; otherwise use localhost */
      arg++;
      if(argc>arg) {
        addr = argv[arg];
        arg++;
      }
    }
    else {
      puts("Usage: sockfilt [option]\n"
           " --version\n"
           " --verbose\n"
           " --logfile [file]\n"
           " --pidfile [file]\n"
           " --portfile [file]\n"
           " --ipv4\n"
           " --ipv6\n"
           " --bindonly\n"
           " --port [port]\n"
           " --connect [port]\n"
           " --addr [address]");
      return 0;
    }
  }

#ifdef _WIN32
  win32_init();
  atexit(win32_cleanup);

  setmode(fileno(stdin), O_BINARY);
  setmode(fileno(stdout), O_BINARY);
  setmode(fileno(stderr), O_BINARY);
#endif

  install_signal_handlers(false);

#ifdef USE_IPV6
  if(!use_ipv6)
#endif
    sock = socket(AF_INET, SOCK_STREAM, 0);
#ifdef USE_IPV6
  else
    sock = socket(AF_INET6, SOCK_STREAM, 0);
#endif

  if(CURL_SOCKET_BAD == sock) {
    error = SOCKERRNO;
    logmsg("Error creating socket: (%d) %s", error, sstrerror(error));
    write_stdout("FAIL\n", 5);
    goto sockfilt_cleanup;
  }

  if(connectport) {
    /* Active mode, we should connect to the given port number */
    mode = ACTIVE;
#ifdef USE_IPV6
    if(!use_ipv6) {
#endif
      memset(&me.sa4, 0, sizeof(me.sa4));
      me.sa4.sin_family = AF_INET;
      me.sa4.sin_port = htons(connectport);
      me.sa4.sin_addr.s_addr = INADDR_ANY;
      if(!addr)
        addr = "127.0.0.1";
      Curl_inet_pton(AF_INET, addr, &me.sa4.sin_addr);

      rc = connect(sock, &me.sa, sizeof(me.sa4));
#ifdef USE_IPV6
    }
    else {
      memset(&me.sa6, 0, sizeof(me.sa6));
      me.sa6.sin6_family = AF_INET6;
      me.sa6.sin6_port = htons(connectport);
      if(!addr)
        addr = "::1";
      Curl_inet_pton(AF_INET6, addr, &me.sa6.sin6_addr);

      rc = connect(sock, &me.sa, sizeof(me.sa6));
    }
#endif /* USE_IPV6 */
    if(rc) {
      error = SOCKERRNO;
      logmsg("Error connecting to port %hu: (%d) %s",
             connectport, error, sstrerror(error));
      write_stdout("FAIL\n", 5);
      goto sockfilt_cleanup;
    }
    logmsg("====> Client connect");
    msgsock = sock; /* use this as stream */
  }
  else {
    /* passive daemon style */
    sock = sockdaemon(sock, &port);
    if(CURL_SOCKET_BAD == sock) {
      write_stdout("FAIL\n", 5);
      goto sockfilt_cleanup;
    }
    msgsock = CURL_SOCKET_BAD; /* no stream socket yet */
  }

  logmsg("Running %s version", ipv_inuse);

  if(connectport)
    logmsg("Connected to port %hu", connectport);
  else if(bind_only)
    logmsg("Bound without listening on port %hu", port);
  else
    logmsg("Listening on port %hu", port);

  wrotepidfile = write_pidfile(pidname);
  if(!wrotepidfile) {
    write_stdout("FAIL\n", 5);
    goto sockfilt_cleanup;
  }
  if(portname) {
    wroteportfile = write_portfile(portname, port);
    if(!wroteportfile) {
      write_stdout("FAIL\n", 5);
      goto sockfilt_cleanup;
    }
  }

  do {
    juggle_again = juggle(&msgsock, sock, &mode);
  } while(juggle_again);

sockfilt_cleanup:

  if((msgsock != sock) && (msgsock != CURL_SOCKET_BAD))
    sclose(msgsock);

  if(sock != CURL_SOCKET_BAD)
    sclose(sock);

  if(wrotepidfile)
    unlink(pidname);
  if(wroteportfile)
    unlink(portname);

  restore_signal_handlers(false);

  if(got_exit_signal) {
    logmsg("============> sockfilt exits with signal (%d)", exit_signal);
    /*
     * To properly set the return status of the process we
     * must raise the same signal SIGINT or SIGTERM that we
     * caught and let the old handler take care of it.
     */
    raise(exit_signal);
  }

  logmsg("============> sockfilt quits");
  return 0;
}
