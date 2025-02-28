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

#ifndef UNDER_CE
#include <signal.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef _XOPEN_SOURCE_EXTENDED
/* This define is "almost" required to build on HP-UX 11 */
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_POLL_H
#include <poll.h>
#elif defined(HAVE_SYS_POLL_H)
#include <sys/poll.h>
#endif

#ifdef MSDOS
#include <dos.h>  /* delay() */
#endif

#ifdef _WIN32
#include "strerror.h"
#endif

#include "curlx.h" /* from the private lib dir */
#include "getpart.h"
#include "util.h"
#include "timeval.h"

#ifdef USE_WINSOCK
#undef  EINTR
#define EINTR    4 /* errno.h value */
#undef  EINVAL
#define EINVAL  22 /* errno.h value */
#endif

static struct timeval tvnow(void);

/* This function returns a pointer to STATIC memory. It converts the given
 * binary lump to a hex formatted string usable for output in logs or
 * whatever.
 */
char *data_to_hex(char *data, size_t len)
{
  static char buf[256*3];
  size_t i;
  char *optr = buf;
  char *iptr = data;

  if(len > 255)
    len = 255;

  for(i = 0; i < len; i++) {
    if((data[i] >= 0x20) && (data[i] < 0x7f))
      *optr++ = *iptr++;
    else {
      msnprintf(optr, 4, "%%%02x", *iptr++);
      optr += 3;
    }
  }
  *optr = 0; /* in case no sprintf was used */

  return buf;
}

void logmsg(const char *msg, ...)
{
  va_list ap;
  char buffer[2048 + 1];
  FILE *logfp;
  struct timeval tv;
  time_t sec;
  struct tm *now;
  char timebuf[20];
  static time_t epoch_offset;
  static int    known_offset;

  if(!serverlogfile) {
    fprintf(stderr, "Error: serverlogfile not set\n");
    return;
  }

  tv = tvnow();
  if(!known_offset) {
    epoch_offset = time(NULL) - tv.tv_sec;
    known_offset = 1;
  }
  sec = epoch_offset + tv.tv_sec;
  /* !checksrc! disable BANNEDFUNC 1 */
  now = localtime(&sec); /* not thread safe but we don't care */

  msnprintf(timebuf, sizeof(timebuf), "%02d:%02d:%02d.%06ld",
            (int)now->tm_hour, (int)now->tm_min, (int)now->tm_sec,
            (long)tv.tv_usec);

  va_start(ap, msg);
  mvsnprintf(buffer, sizeof(buffer), msg, ap);
  va_end(ap);

  do {
    logfp = fopen(serverlogfile, "ab");
  } while(!logfp && (errno == EINTR));
  if(logfp) {
    fprintf(logfp, "%s %s\n", timebuf, buffer);
    fclose(logfp);
  }
  else {
    int error = errno;
    fprintf(stderr, "fopen() failed with error: %d %s\n",
            error, strerror(error));
    fprintf(stderr, "Error opening file: %s\n", serverlogfile);
    fprintf(stderr, "Msg not logged: %s %s\n", timebuf, buffer);
  }
}

#ifdef _WIN32
/* use instead of perror() on generic Windows */
void win32_perror(const char *msg)
{
  char buf[512];
  int err = SOCKERRNO;
  Curl_winapi_strerror(err, buf, sizeof(buf));
  if(msg)
    fprintf(stderr, "%s: ", msg);
  fprintf(stderr, "%s\n", buf);
}

static void win32_cleanup(void)
{
#ifdef USE_WINSOCK
  WSACleanup();
#endif  /* USE_WINSOCK */

  /* flush buffers of all streams regardless of their mode */
  _flushall();
}

int win32_init(void)
{
#ifdef USE_WINSOCK
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;

  wVersionRequested = MAKEWORD(2, 2);
  err = WSAStartup(wVersionRequested, &wsaData);

  if(err) {
    perror("Winsock init failed");
    logmsg("Error initialising Winsock -- aborting");
    return 1;
  }

  if(LOBYTE(wsaData.wVersion) != LOBYTE(wVersionRequested) ||
     HIBYTE(wsaData.wVersion) != HIBYTE(wVersionRequested) ) {
    WSACleanup();
    perror("Winsock init failed");
    logmsg("No suitable winsock.dll found -- aborting");
    return 1;
  }
#endif  /* USE_WINSOCK */
  atexit(win32_cleanup);
  return 0;
}

/* socket-safe strerror (works on Winsock errors, too) */
const char *sstrerror(int err)
{
  static char buf[512];
  return Curl_winapi_strerror(err, buf, sizeof(buf));
}
#endif  /* _WIN32 */

/* set by the main code to point to where the test dir is */
const char *path = ".";

FILE *test2fopen(long testno, const char *logdir)
{
  FILE *stream;
  char filename[256];
  /* first try the alternative, preprocessed, file */
  msnprintf(filename, sizeof(filename), ALTTEST_DATA_PATH, logdir, testno);
  stream = fopen(filename, "rb");
  if(stream)
    return stream;

  /* then try the source version */
  msnprintf(filename, sizeof(filename), TEST_DATA_PATH, path, testno);
  stream = fopen(filename, "rb");

  return stream;
}

/*
 * Portable function used for waiting a specific amount of ms.
 * Waiting indefinitely with this function is not allowed, a
 * zero or negative timeout value will return immediately.
 *
 * Return values:
 *   -1 = system call error, or invalid timeout value
 *    0 = specified timeout has elapsed
 */
int wait_ms(int timeout_ms)
{
#if !defined(MSDOS) && !defined(USE_WINSOCK)
#ifndef HAVE_POLL
  struct timeval pending_tv;
#endif
  struct timeval initial_tv;
  int pending_ms;
#endif
  int r = 0;

  if(!timeout_ms)
    return 0;
  if(timeout_ms < 0) {
    CURL_SETERRNO(EINVAL);
    return -1;
  }
#if defined(MSDOS)
  delay(timeout_ms);
#elif defined(USE_WINSOCK)
  Sleep((DWORD)timeout_ms);
#else
  pending_ms = timeout_ms;
  initial_tv = tvnow();
  do {
    int error;
#ifdef HAVE_POLL
    r = poll(NULL, 0, pending_ms);
#else
    pending_tv.tv_sec = pending_ms / 1000;
    pending_tv.tv_usec = (pending_ms % 1000) * 1000;
    r = select(0, NULL, NULL, NULL, &pending_tv);
#endif /* HAVE_POLL */
    if(r != -1)
      break;
    error = errno;
    if(error && (error != EINTR))
      break;
    pending_ms = timeout_ms - (int)timediff(tvnow(), initial_tv);
    if(pending_ms <= 0)
      break;
  } while(r == -1);
#endif /* USE_WINSOCK */
  if(r)
    r = -1;
  return r;
}

curl_off_t our_getpid(void)
{
  curl_off_t pid;

  pid = (curl_off_t)Curl_getpid();
#if defined(_WIN32)
  /* store pid + MAX_PID to avoid conflict with Cygwin/msys PIDs, see also:
   * - 2019-01-31: https://cygwin.com/git/?p=newlib-cygwin.git;a=commit; ↵
   *               h=b5e1003722cb14235c4f166be72c09acdffc62ea
   * - 2019-02-02: https://cygwin.com/git/?p=newlib-cygwin.git;a=commit; ↵
   *               h=448cf5aa4b429d5a9cebf92a0da4ab4b5b6d23fe
   * - 2024-12-19: https://cygwin.com/git/?p=newlib-cygwin.git;a=commit; ↵
   *               h=363357c023ce01e936bdaedf0f479292a8fa4e0f
   */
  pid += 4194304;
#endif
  return pid;
}

int write_pidfile(const char *filename)
{
  FILE *pidfile;
  curl_off_t pid;

  pid = our_getpid();
  pidfile = fopen(filename, "wb");
  if(!pidfile) {
    logmsg("Couldn't write pid file: %s %s", filename, strerror(errno));
    return 0; /* fail */
  }
  fprintf(pidfile, "%" CURL_FORMAT_CURL_OFF_T "\n", pid);
  fclose(pidfile);
  logmsg("Wrote pid %" CURL_FORMAT_CURL_OFF_T " to %s", pid, filename);
  return 1; /* success */
}

/* store the used port number in a file */
int write_portfile(const char *filename, int port)
{
  FILE *portfile = fopen(filename, "wb");
  if(!portfile) {
    logmsg("Couldn't write port file: %s %s", filename, strerror(errno));
    return 0; /* fail */
  }
  fprintf(portfile, "%d\n", port);
  fclose(portfile);
  logmsg("Wrote port %d to %s", port, filename);
  return 1; /* success */
}

void set_advisor_read_lock(const char *filename)
{
  FILE *lockfile;
  int error = 0;
  int res;

  do {
    lockfile = fopen(filename, "wb");
  } while(!lockfile && ((error = errno) == EINTR));
  if(!lockfile) {
    logmsg("Error creating lock file %s error: %d %s",
           filename, error, strerror(error));
    return;
  }

  res = fclose(lockfile);
  if(res)
    logmsg("Error closing lock file %s error: %d %s",
           filename, errno, strerror(errno));
}

void clear_advisor_read_lock(const char *filename)
{
  int error = 0;
  int res;

  /*
  ** Log all removal failures. Even those due to file not existing.
  ** This allows to detect if unexpectedly the file has already been
  ** removed by a process different than the one that should do this.
  */

  do {
    res = unlink(filename);
  } while(res && ((error = errno) == EINTR));
  if(res)
    logmsg("Error removing lock file %s error: %d %s",
           filename, error, strerror(error));
}


#if defined(_WIN32)

static struct timeval tvnow(void)
{
  /*
  ** GetTickCount() is available on _all_ Windows versions from W95 up
  ** to nowadays. Returns milliseconds elapsed since last system boot,
  ** increases monotonically and wraps once 49.7 days have elapsed.
  **
  ** GetTickCount64() is available on Windows version from Windows Vista
  ** and Windows Server 2008 up to nowadays. The resolution of the
  ** function is limited to the resolution of the system timer, which
  ** is typically in the range of 10 milliseconds to 16 milliseconds.
  */
  struct timeval now;
#if defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0600)
  ULONGLONG milliseconds = GetTickCount64();
#else
  DWORD milliseconds = GetTickCount();
#endif
  now.tv_sec = (long)(milliseconds / 1000);
  now.tv_usec = (long)((milliseconds % 1000) * 1000);
  return now;
}

#elif defined(HAVE_CLOCK_GETTIME_MONOTONIC)

static struct timeval tvnow(void)
{
  /*
  ** clock_gettime() is granted to be increased monotonically when the
  ** monotonic clock is queried. Time starting point is unspecified, it
  ** could be the system start-up time, the Epoch, or something else,
  ** in any case the time starting point does not change once that the
  ** system has started up.
  */
  struct timeval now;
  struct timespec tsnow;
  if(0 == clock_gettime(CLOCK_MONOTONIC, &tsnow)) {
    now.tv_sec = tsnow.tv_sec;
    now.tv_usec = (int)(tsnow.tv_nsec / 1000);
  }
  /*
  ** Even when the configure process has truly detected monotonic clock
  ** availability, it might happen that it is not actually available at
  ** run-time. When this occurs simply fallback to other time source.
  */
#ifdef HAVE_GETTIMEOFDAY
  else
    (void)gettimeofday(&now, NULL);
#else
  else {
    now.tv_sec = time(NULL);
    now.tv_usec = 0;
  }
#endif
  return now;
}

#elif defined(HAVE_GETTIMEOFDAY)

static struct timeval tvnow(void)
{
  /*
  ** gettimeofday() is not granted to be increased monotonically, due to
  ** clock drifting and external source time synchronization it can jump
  ** forward or backward in time.
  */
  struct timeval now;
  (void)gettimeofday(&now, NULL);
  return now;
}

#else

static struct timeval tvnow(void)
{
  /*
  ** time() returns the value of time in seconds since the Epoch.
  */
  struct timeval now;
  now.tv_sec = time(NULL);
  now.tv_usec = 0;
  return now;
}

#endif

long timediff(struct timeval newer, struct timeval older)
{
  timediff_t diff = newer.tv_sec-older.tv_sec;
  if(diff >= (LONG_MAX/1000))
    return LONG_MAX;
  else if(diff <= (LONG_MIN/1000))
    return LONG_MIN;
  return (long)(newer.tv_sec-older.tv_sec)*1000+
    (long)(newer.tv_usec-older.tv_usec)/1000;
}

/* vars used to keep around previous signal handlers */

typedef void (*SIGHANDLER_T)(int);

#if defined(_MSC_VER) && (_MSC_VER <= 1700)
/* Workaround for warning C4306:
   'type cast' : conversion from 'int' to 'void (__cdecl *)(int)' */
#undef SIG_ERR
#define SIG_ERR  ((SIGHANDLER_T)(size_t)-1)
#endif

#ifdef SIGHUP
static SIGHANDLER_T old_sighup_handler  = SIG_ERR;
#endif

#ifdef SIGPIPE
static SIGHANDLER_T old_sigpipe_handler = SIG_ERR;
#endif

#ifdef SIGALRM
static SIGHANDLER_T old_sigalrm_handler = SIG_ERR;
#endif

#ifdef SIGINT
static SIGHANDLER_T old_sigint_handler  = SIG_ERR;
#endif

#ifdef SIGTERM
static SIGHANDLER_T old_sigterm_handler = SIG_ERR;
#endif

#if defined(SIGBREAK) && defined(_WIN32)
static SIGHANDLER_T old_sigbreak_handler = SIG_ERR;
#endif

#if defined(_WIN32) && !defined(CURL_WINDOWS_UWP) && !defined(UNDER_CE)
static unsigned int thread_main_id = 0;
static HANDLE thread_main_window = NULL;
static HWND hidden_main_window = NULL;
#endif

/* var which if set indicates that the program should finish execution */
volatile int got_exit_signal = 0;

/* if next is set indicates the first signal handled in exit_signal_handler */
volatile int exit_signal = 0;

#ifdef _WIN32
/* event which if set indicates that the program should finish */
HANDLE exit_event = NULL;
#endif

/* signal handler that will be triggered to indicate that the program
 * should finish its execution in a controlled manner as soon as possible.
 * The first time this is called it will set got_exit_signal to one and
 * store in exit_signal the signal that triggered its execution.
 */
#ifndef UNDER_CE
static void exit_signal_handler(int signum)
{
  int old_errno = errno;
  logmsg("exit_signal_handler: %d", signum);
  if(got_exit_signal == 0) {
    got_exit_signal = 1;
    exit_signal = signum;
#ifdef _WIN32
    if(exit_event)
      (void)SetEvent(exit_event);
#endif
  }
  (void)signal(signum, exit_signal_handler);
  CURL_SETERRNO(old_errno);
}
#endif

#if defined(_WIN32) && !defined(UNDER_CE)
/* CTRL event handler for Windows Console applications to simulate
 * SIGINT, SIGTERM and SIGBREAK on CTRL events and trigger signal handler.
 *
 * Background information from MSDN:
 * SIGINT is not supported for any Win32 application. When a CTRL+C
 * interrupt occurs, Win32 operating systems generate a new thread
 * to specifically handle that interrupt. This can cause a single-thread
 * application, such as one in UNIX, to become multithreaded and cause
 * unexpected behavior.
 * [...]
 * The SIGILL and SIGTERM signals are not generated under Windows.
 * They are included for ANSI compatibility. Therefore, you can set
 * signal handlers for these signals by using signal, and you can also
 * explicitly generate these signals by calling raise. Source:
 * https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/signal
 */
static BOOL WINAPI ctrl_event_handler(DWORD dwCtrlType)
{
  int signum = 0;
  logmsg("ctrl_event_handler: %lu", dwCtrlType);
  switch(dwCtrlType) {
#ifdef SIGINT
  case CTRL_C_EVENT:
    signum = SIGINT;
    break;
#endif
#ifdef SIGTERM
  case CTRL_CLOSE_EVENT:
    signum = SIGTERM;
    break;
#endif
#ifdef SIGBREAK
  case CTRL_BREAK_EVENT:
    signum = SIGBREAK;
    break;
#endif
  default:
    return FALSE;
  }
  if(signum) {
    logmsg("ctrl_event_handler: %lu -> %d", dwCtrlType, signum);
    raise(signum);
  }
  return TRUE;
}
#endif

#if defined(_WIN32) && !defined(CURL_WINDOWS_UWP) && !defined(UNDER_CE)
/* Window message handler for Windows applications to add support
 * for graceful process termination via taskkill (without /f) which
 * sends WM_CLOSE to all Windows of a process (even hidden ones).
 *
 * Therefore we create and run a hidden Window in a separate thread
 * to receive and handle the WM_CLOSE message as SIGTERM signal.
 */
static LRESULT CALLBACK main_window_proc(HWND hwnd, UINT uMsg,
                                         WPARAM wParam, LPARAM lParam)
{
  int signum = 0;
  if(hwnd == hidden_main_window) {
    switch(uMsg) {
#ifdef SIGTERM
      case WM_CLOSE:
        signum = SIGTERM;
        break;
#endif
    case WM_DESTROY:
      PostQuitMessage(0);
      break;
    }
    if(signum) {
      logmsg("main_window_proc: %d -> %d", uMsg, signum);
      raise(signum);
    }
  }
  return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
/* Window message queue loop for hidden main window, details see above.
 */
#include <process.h>
static unsigned int WINAPI main_window_loop(void *lpParameter)
{
  WNDCLASS wc;
  BOOL ret;
  MSG msg;

  ZeroMemory(&wc, sizeof(wc));
  wc.lpfnWndProc = (WNDPROC)main_window_proc;
  wc.hInstance = (HINSTANCE)lpParameter;
  wc.lpszClassName = TEXT("MainWClass");
  if(!RegisterClass(&wc)) {
    perror("RegisterClass failed");
    return (DWORD)-1;
  }

  hidden_main_window = CreateWindowEx(0, TEXT("MainWClass"),
                                      TEXT("Recv WM_CLOSE msg"),
                                      WS_OVERLAPPEDWINDOW,
                                      CW_USEDEFAULT, CW_USEDEFAULT,
                                      CW_USEDEFAULT, CW_USEDEFAULT,
                                      (HWND)NULL, (HMENU)NULL,
                                      wc.hInstance, (LPVOID)NULL);
  if(!hidden_main_window) {
    perror("CreateWindowEx failed");
    return (DWORD)-1;
  }

  do {
    ret = GetMessage(&msg, NULL, 0, 0);
    if(ret == -1) {
      perror("GetMessage failed");
      return (DWORD)-1;
    }
    else if(ret) {
      if(msg.message == WM_APP) {
        DestroyWindow(hidden_main_window);
      }
      else if(msg.hwnd && !TranslateMessage(&msg)) {
        DispatchMessage(&msg);
      }
    }
  } while(ret);

  hidden_main_window = NULL;
  return (DWORD)msg.wParam;
}
#endif

#ifndef UNDER_CE
static SIGHANDLER_T set_signal(int signum, SIGHANDLER_T handler,
                               bool restartable)
{
#if defined(HAVE_SIGACTION) && defined(SA_RESTART)
  struct sigaction sa, oldsa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, signum);
  sa.sa_flags = restartable ? SA_RESTART : 0;

  if(sigaction(signum, &sa, &oldsa))
    return SIG_ERR;

  return oldsa.sa_handler;
#else
  SIGHANDLER_T oldhdlr = signal(signum, handler);

#ifdef HAVE_SIGINTERRUPT
  if(oldhdlr != SIG_ERR)
    siginterrupt(signum, (int) restartable);
#else
  (void) restartable;
#endif

  return oldhdlr;
#endif
}
#endif

void install_signal_handlers(bool keep_sigalrm)
{
#ifdef _WIN32
  /* setup Windows exit event before any signal can trigger */
  exit_event = CreateEvent(NULL, TRUE, FALSE, NULL);
  if(!exit_event)
    logmsg("cannot create exit event");
#endif
#ifdef SIGHUP
  /* ignore SIGHUP signal */
  old_sighup_handler = set_signal(SIGHUP, SIG_IGN, FALSE);
  if(old_sighup_handler == SIG_ERR)
    logmsg("cannot install SIGHUP handler: %s", strerror(errno));
#endif
#ifdef SIGPIPE
  /* ignore SIGPIPE signal */
  old_sigpipe_handler = set_signal(SIGPIPE, SIG_IGN, FALSE);
  if(old_sigpipe_handler == SIG_ERR)
    logmsg("cannot install SIGPIPE handler: %s", strerror(errno));
#endif
#ifdef SIGALRM
  if(!keep_sigalrm) {
    /* ignore SIGALRM signal */
    old_sigalrm_handler = set_signal(SIGALRM, SIG_IGN, FALSE);
    if(old_sigalrm_handler == SIG_ERR)
      logmsg("cannot install SIGALRM handler: %s", strerror(errno));
  }
#else
  (void)keep_sigalrm;
#endif
#ifdef SIGINT
  /* handle SIGINT signal with our exit_signal_handler */
  old_sigint_handler = set_signal(SIGINT, exit_signal_handler, TRUE);
  if(old_sigint_handler == SIG_ERR)
    logmsg("cannot install SIGINT handler: %s", strerror(errno));
#endif
#ifdef SIGTERM
  /* handle SIGTERM signal with our exit_signal_handler */
  old_sigterm_handler = set_signal(SIGTERM, exit_signal_handler, TRUE);
  if(old_sigterm_handler == SIG_ERR)
    logmsg("cannot install SIGTERM handler: %s", strerror(errno));
#endif
#if defined(SIGBREAK) && defined(_WIN32)
  /* handle SIGBREAK signal with our exit_signal_handler */
  old_sigbreak_handler = set_signal(SIGBREAK, exit_signal_handler, TRUE);
  if(old_sigbreak_handler == SIG_ERR)
    logmsg("cannot install SIGBREAK handler: %s", strerror(errno));
#endif
#ifdef _WIN32
#ifndef UNDER_CE
  if(!SetConsoleCtrlHandler(ctrl_event_handler, TRUE))
    logmsg("cannot install CTRL event handler");
#endif

#if !defined(CURL_WINDOWS_UWP) && !defined(UNDER_CE)
  {
    typedef uintptr_t curl_win_thread_handle_t;
    curl_win_thread_handle_t thread;
    thread = _beginthreadex(NULL, 0, &main_window_loop,
                            (void *)GetModuleHandle(NULL), 0, &thread_main_id);
    thread_main_window = (HANDLE)thread;
    if(!thread_main_window || !thread_main_id)
      logmsg("cannot start main window loop");
  }
#endif
#endif
}

void restore_signal_handlers(bool keep_sigalrm)
{
#ifdef SIGHUP
  if(SIG_ERR != old_sighup_handler)
    (void) set_signal(SIGHUP, old_sighup_handler, FALSE);
#endif
#ifdef SIGPIPE
  if(SIG_ERR != old_sigpipe_handler)
    (void) set_signal(SIGPIPE, old_sigpipe_handler, FALSE);
#endif
#ifdef SIGALRM
  if(!keep_sigalrm) {
    if(SIG_ERR != old_sigalrm_handler)
      (void) set_signal(SIGALRM, old_sigalrm_handler, FALSE);
  }
#else
  (void)keep_sigalrm;
#endif
#ifdef SIGINT
  if(SIG_ERR != old_sigint_handler)
    (void) set_signal(SIGINT, old_sigint_handler, FALSE);
#endif
#ifdef SIGTERM
  if(SIG_ERR != old_sigterm_handler)
    (void) set_signal(SIGTERM, old_sigterm_handler, FALSE);
#endif
#if defined(SIGBREAK) && defined(_WIN32)
  if(SIG_ERR != old_sigbreak_handler)
    (void) set_signal(SIGBREAK, old_sigbreak_handler, FALSE);
#endif
#ifdef _WIN32
#ifndef UNDER_CE
  (void)SetConsoleCtrlHandler(ctrl_event_handler, FALSE);
#endif
#if !defined(CURL_WINDOWS_UWP) && !defined(UNDER_CE)
  if(thread_main_window && thread_main_id) {
    if(PostThreadMessage(thread_main_id, WM_APP, 0, 0)) {
      if(WaitForSingleObjectEx(thread_main_window, INFINITE, TRUE)) {
        if(CloseHandle(thread_main_window)) {
          thread_main_window = NULL;
          thread_main_id = 0;
        }
      }
    }
  }
  if(exit_event) {
    if(CloseHandle(exit_event)) {
      exit_event = NULL;
    }
  }
#endif
#endif
}

#ifdef USE_UNIX_SOCKETS

int bind_unix_socket(curl_socket_t sock, const char *unix_socket,
                     struct sockaddr_un *sau)
{
  int error;
  int rc;
  size_t len = strlen(unix_socket);

  memset(sau, 0, sizeof(struct sockaddr_un));
  sau->sun_family = AF_UNIX;
  if(len >= sizeof(sau->sun_path) - 1) {
    logmsg("Too long unix socket domain path (%zd)", len);
    return -1;
  }
  strcpy(sau->sun_path, unix_socket);
  rc = bind(sock, (struct sockaddr*)sau, sizeof(struct sockaddr_un));
  if(0 != rc && SOCKERRNO == EADDRINUSE) {
    struct_stat statbuf;
    /* socket already exists. Perhaps it is stale? */
    curl_socket_t unixfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(CURL_SOCKET_BAD == unixfd) {
      logmsg("Failed to create socket at %s: (%d) %s",
             unix_socket, SOCKERRNO, sstrerror(SOCKERRNO));
      return -1;
    }
    /* check whether the server is alive */
    rc = connect(unixfd, (struct sockaddr*)sau, sizeof(struct sockaddr_un));
    error = SOCKERRNO;
    sclose(unixfd);
    if(0 != rc && ECONNREFUSED != error) {
      logmsg("Failed to connect to %s: (%d) %s",
             unix_socket, error, sstrerror(error));
      return rc;
    }
    /* socket server is not alive, now check if it was actually a socket. */
#ifdef _WIN32
    /* Windows does not have lstat function. */
    rc = curlx_win32_stat(unix_socket, &statbuf);
#else
    rc = lstat(unix_socket, &statbuf);
#endif
    if(0 != rc) {
      logmsg("Error binding socket, failed to stat %s: (%d) %s",
             unix_socket, errno, strerror(errno));
      return rc;
    }
#ifdef S_IFSOCK
    if((statbuf.st_mode & S_IFSOCK) != S_IFSOCK) {
      logmsg("Error binding socket, failed to stat %s", unix_socket);
      return -1;
    }
#endif
    /* dead socket, cleanup and retry bind */
    rc = unlink(unix_socket);
    if(0 != rc) {
      logmsg("Error binding socket, failed to unlink %s: (%d) %s",
             unix_socket, errno, strerror(errno));
      return rc;
    }
    /* stale socket is gone, retry bind */
    rc = bind(sock, (struct sockaddr*)sau, sizeof(struct sockaddr_un));
  }
  return rc;
}
#endif

/*
** unsigned long to unsigned short
*/
#define CURL_MASK_USHORT  ((unsigned short)~0)
#define CURL_MASK_SSHORT  (CURL_MASK_USHORT >> 1)

unsigned short util_ultous(unsigned long ulnum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  DEBUGASSERT(ulnum <= (unsigned long) CURL_MASK_USHORT);
  return (unsigned short)(ulnum & (unsigned long) CURL_MASK_USHORT);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}
