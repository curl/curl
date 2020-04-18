/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "server_setup.h"

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef _XOPEN_SOURCE_EXTENDED
/* This define is "almost" required to build on HPUX 11 */
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
#ifdef __MINGW32__
#include <w32api.h>
#endif

#define ENABLE_CURLX_PRINTF
/* make the curlx header define all printf() functions to use the curlx_*
   versions instead */
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

/* MinGW with w32api version < 3.6 declared in6addr_any as extern,
   but lacked the definition */
#if defined(ENABLE_IPV6) && defined(__MINGW32__)
#if (__W32API_MAJOR_VERSION < 3) || \
    ((__W32API_MAJOR_VERSION == 3) && (__W32API_MINOR_VERSION < 6))
const struct in6_addr in6addr_any = {{ IN6ADDR_ANY_INIT }};
#endif /* w32api < 3.6 */
#endif /* ENABLE_IPV6 && __MINGW32__*/

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
  now = localtime(&sec); /* not thread safe but we don't care */

  msnprintf(timebuf, sizeof(timebuf), "%02d:%02d:%02d.%06ld",
            (int)now->tm_hour, (int)now->tm_min, (int)now->tm_sec,
            (long)tv.tv_usec);

  va_start(ap, msg);
  mvsnprintf(buffer, sizeof(buffer), msg, ap);
  va_end(ap);

  logfp = fopen(serverlogfile, "ab");
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

#ifdef WIN32
/* use instead of perror() on generic windows */
void win32_perror(const char *msg)
{
  char buf[512];
  DWORD err = SOCKERRNO;

  if(!FormatMessageA((FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS), NULL, err,
                     LANG_NEUTRAL, buf, sizeof(buf), NULL))
    msnprintf(buf, sizeof(buf), "Unknown error %lu (%#lx)", err, err);
  if(msg)
    fprintf(stderr, "%s: ", msg);
  fprintf(stderr, "%s\n", buf);
}
#endif  /* WIN32 */

#ifdef USE_WINSOCK
void win32_init(void)
{
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;
  wVersionRequested = MAKEWORD(USE_WINSOCK, USE_WINSOCK);

  err = WSAStartup(wVersionRequested, &wsaData);

  if(err != 0) {
    perror("Winsock init failed");
    logmsg("Error initialising winsock -- aborting");
    exit(1);
  }

  if(LOBYTE(wsaData.wVersion) != USE_WINSOCK ||
     HIBYTE(wsaData.wVersion) != USE_WINSOCK) {
    WSACleanup();
    perror("Winsock init failed");
    logmsg("No suitable winsock.dll found -- aborting");
    exit(1);
  }
}

void win32_cleanup(void)
{
  WSACleanup();
}
#endif  /* USE_WINSOCK */

/* set by the main code to point to where the test dir is */
const char *path = ".";

FILE *test2fopen(long testno)
{
  FILE *stream;
  char filename[256];
  /* first try the alternative, preprocessed, file */
  msnprintf(filename, sizeof(filename), ALTTEST_DATA_PATH, ".", testno);
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
#ifndef HAVE_POLL_FINE
  struct timeval pending_tv;
#endif
  struct timeval initial_tv;
  int pending_ms;
#endif
  int r = 0;

  if(!timeout_ms)
    return 0;
  if(timeout_ms < 0) {
    errno = EINVAL;
    return -1;
  }
#if defined(MSDOS)
  delay(timeout_ms);
#elif defined(USE_WINSOCK)
  Sleep(timeout_ms);
#else
  pending_ms = timeout_ms;
  initial_tv = tvnow();
  do {
    int error;
#if defined(HAVE_POLL_FINE)
    r = poll(NULL, 0, pending_ms);
#else
    pending_tv.tv_sec = pending_ms / 1000;
    pending_tv.tv_usec = (pending_ms % 1000) * 1000;
    r = select(0, NULL, NULL, NULL, &pending_tv);
#endif /* HAVE_POLL_FINE */
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

int write_pidfile(const char *filename)
{
  FILE *pidfile;
  curl_off_t pid;

  pid = (curl_off_t)getpid();
  pidfile = fopen(filename, "wb");
  if(!pidfile) {
    logmsg("Couldn't write pid file: %s %s", filename, strerror(errno));
    return 0; /* fail */
  }
#if defined(WIN32) || defined(_WIN32)
  /* store pid + 65536 to avoid conflict with Cygwin/msys PIDs, see also:
   * - https://cygwin.com/git/?p=newlib-cygwin.git;a=commit; ↵
   *   h=b5e1003722cb14235c4f166be72c09acdffc62ea
   * - https://cygwin.com/git/?p=newlib-cygwin.git;a=commit; ↵
   *   h=448cf5aa4b429d5a9cebf92a0da4ab4b5b6d23fe
   */
  pid += 65536;
#endif
  fprintf(pidfile, "%" CURL_FORMAT_CURL_OFF_T "\n", pid);
  fclose(pidfile);
  logmsg("Wrote pid %ld to %s", pid, filename);
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
  } while((lockfile == NULL) && ((error = errno) == EINTR));
  if(lockfile == NULL) {
    logmsg("Error creating lock file %s error: %d %s",
           filename, error, strerror(error));
    return;
  }

  do {
    res = fclose(lockfile);
  } while(res && ((error = errno) == EINTR));
  if(res)
    logmsg("Error closing lock file %s error: %d %s",
           filename, error, strerror(error));
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


/* Portable, consistent toupper (remember EBCDIC). Do not use toupper() because
   its behavior is altered by the current locale. */
static char raw_toupper(char in)
{
#if !defined(CURL_DOES_CONVERSIONS)
  if(in >= 'a' && in <= 'z')
    return (char)('A' + in - 'a');
#else
  switch(in) {
  case 'a':
    return 'A';
  case 'b':
    return 'B';
  case 'c':
    return 'C';
  case 'd':
    return 'D';
  case 'e':
    return 'E';
  case 'f':
    return 'F';
  case 'g':
    return 'G';
  case 'h':
    return 'H';
  case 'i':
    return 'I';
  case 'j':
    return 'J';
  case 'k':
    return 'K';
  case 'l':
    return 'L';
  case 'm':
    return 'M';
  case 'n':
    return 'N';
  case 'o':
    return 'O';
  case 'p':
    return 'P';
  case 'q':
    return 'Q';
  case 'r':
    return 'R';
  case 's':
    return 'S';
  case 't':
    return 'T';
  case 'u':
    return 'U';
  case 'v':
    return 'V';
  case 'w':
    return 'W';
  case 'x':
    return 'X';
  case 'y':
    return 'Y';
  case 'z':
    return 'Z';
  }
#endif

  return in;
}

int strncasecompare(const char *first, const char *second, size_t max)
{
  while(*first && *second && max) {
    if(raw_toupper(*first) != raw_toupper(*second)) {
      break;
    }
    max--;
    first++;
    second++;
  }
  if(0 == max)
    return 1; /* they are equal this far */

  return raw_toupper(*first) == raw_toupper(*second);
}

#if defined(WIN32) && !defined(MSDOS)

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
#if defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0600) && \
    (!defined(__MINGW32__) || defined(__MINGW64_VERSION_MAJOR))
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
    now.tv_usec = tsnow.tv_nsec / 1000;
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
    now.tv_sec = (long)time(NULL);
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
  now.tv_sec = (long)time(NULL);
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

/* do-nothing macro replacement for systems which lack siginterrupt() */

#ifndef HAVE_SIGINTERRUPT
#define siginterrupt(x,y) do {} while(0)
#endif

/* vars used to keep around previous signal handlers */

typedef RETSIGTYPE (*SIGHANDLER_T)(int);

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

#if defined(SIGBREAK) && defined(WIN32)
static SIGHANDLER_T old_sigbreak_handler = SIG_ERR;
#endif

#ifdef WIN32
static DWORD thread_main_id = 0;
static HANDLE thread_main_window = NULL;
static HWND hidden_main_window = NULL;
#endif

/* var which if set indicates that the program should finish execution */
volatile int got_exit_signal = 0;

/* if next is set indicates the first signal handled in exit_signal_handler */
volatile int exit_signal = 0;

#ifdef WIN32
/* event which if set indicates that the program should finish */
HANDLE exit_event = NULL;
#endif

/* signal handler that will be triggered to indicate that the program
 * should finish its execution in a controlled manner as soon as possible.
 * The first time this is called it will set got_exit_signal to one and
 * store in exit_signal the signal that triggered its execution.
 */
static RETSIGTYPE exit_signal_handler(int signum)
{
  int old_errno = errno;
  logmsg("exit_signal_handler: %d", signum);
  if(got_exit_signal == 0) {
    got_exit_signal = 1;
    exit_signal = signum;
#ifdef WIN32
    if(exit_event)
      (void)SetEvent(exit_event);
#endif
  }
  (void)signal(signum, exit_signal_handler);
  errno = old_errno;
}

#ifdef WIN32
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
 * https://docs.microsoft.com/de-de/cpp/c-runtime-library/reference/signal
 */
static BOOL WINAPI ctrl_event_handler(DWORD dwCtrlType)
{
  int signum = 0;
  logmsg("ctrl_event_handler: %d", dwCtrlType);
  switch(dwCtrlType) {
#ifdef SIGINT
    case CTRL_C_EVENT: signum = SIGINT; break;
#endif
#ifdef SIGTERM
    case CTRL_CLOSE_EVENT: signum = SIGTERM; break;
#endif
#ifdef SIGBREAK
    case CTRL_BREAK_EVENT: signum = SIGBREAK; break;
#endif
    default: return FALSE;
  }
  if(signum) {
    logmsg("ctrl_event_handler: %d -> %d", dwCtrlType, signum);
    raise(signum);
  }
  return TRUE;
}
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
      case WM_CLOSE: signum = SIGTERM; break;
#endif
      case WM_DESTROY: PostQuitMessage(0); break;
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
static DWORD WINAPI main_window_loop(LPVOID lpParameter)
{
  WNDCLASS wc;
  BOOL ret;
  MSG msg;

  ZeroMemory(&wc, sizeof(wc));
  wc.lpfnWndProc = (WNDPROC)main_window_proc;
  wc.hInstance = (HINSTANCE)lpParameter;
  wc.lpszClassName = "MainWClass";
  if(!RegisterClass(&wc)) {
    perror("RegisterClass failed");
    return (DWORD)-1;
  }

  hidden_main_window = CreateWindowEx(0, "MainWClass", "Recv WM_CLOSE msg",
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

void install_signal_handlers(bool keep_sigalrm)
{
#ifdef WIN32
  /* setup windows exit event before any signal can trigger */
  exit_event = CreateEvent(NULL, TRUE, FALSE, NULL);
  if(!exit_event)
    logmsg("cannot create exit event");
#endif
#ifdef SIGHUP
  /* ignore SIGHUP signal */
  old_sighup_handler = signal(SIGHUP, SIG_IGN);
  if(old_sighup_handler == SIG_ERR)
    logmsg("cannot install SIGHUP handler: %s", strerror(errno));
#endif
#ifdef SIGPIPE
  /* ignore SIGPIPE signal */
  old_sigpipe_handler = signal(SIGPIPE, SIG_IGN);
  if(old_sigpipe_handler == SIG_ERR)
    logmsg("cannot install SIGPIPE handler: %s", strerror(errno));
#endif
#ifdef SIGALRM
  if(!keep_sigalrm) {
    /* ignore SIGALRM signal */
    old_sigalrm_handler = signal(SIGALRM, SIG_IGN);
    if(old_sigalrm_handler == SIG_ERR)
      logmsg("cannot install SIGALRM handler: %s", strerror(errno));
  }
#else
  (void)keep_sigalrm;
#endif
#ifdef SIGINT
  /* handle SIGINT signal with our exit_signal_handler */
  old_sigint_handler = signal(SIGINT, exit_signal_handler);
  if(old_sigint_handler == SIG_ERR)
    logmsg("cannot install SIGINT handler: %s", strerror(errno));
  else
    siginterrupt(SIGINT, 1);
#endif
#ifdef SIGTERM
  /* handle SIGTERM signal with our exit_signal_handler */
  old_sigterm_handler = signal(SIGTERM, exit_signal_handler);
  if(old_sigterm_handler == SIG_ERR)
    logmsg("cannot install SIGTERM handler: %s", strerror(errno));
  else
    siginterrupt(SIGTERM, 1);
#endif
#if defined(SIGBREAK) && defined(WIN32)
  /* handle SIGBREAK signal with our exit_signal_handler */
  old_sigbreak_handler = signal(SIGBREAK, exit_signal_handler);
  if(old_sigbreak_handler == SIG_ERR)
    logmsg("cannot install SIGBREAK handler: %s", strerror(errno));
  else
    siginterrupt(SIGBREAK, 1);
#endif
#ifdef WIN32
  if(!SetConsoleCtrlHandler(ctrl_event_handler, TRUE))
    logmsg("cannot install CTRL event handler");
  thread_main_window = CreateThread(NULL, 0,
                                    &main_window_loop,
                                    (LPVOID)GetModuleHandle(NULL),
                                    0, &thread_main_id);
  if(!thread_main_window || !thread_main_id)
    logmsg("cannot start main window loop");
#endif
}

void restore_signal_handlers(bool keep_sigalrm)
{
#ifdef SIGHUP
  if(SIG_ERR != old_sighup_handler)
    (void)signal(SIGHUP, old_sighup_handler);
#endif
#ifdef SIGPIPE
  if(SIG_ERR != old_sigpipe_handler)
    (void)signal(SIGPIPE, old_sigpipe_handler);
#endif
#ifdef SIGALRM
  if(!keep_sigalrm) {
    if(SIG_ERR != old_sigalrm_handler)
      (void)signal(SIGALRM, old_sigalrm_handler);
  }
#else
  (void)keep_sigalrm;
#endif
#ifdef SIGINT
  if(SIG_ERR != old_sigint_handler)
    (void)signal(SIGINT, old_sigint_handler);
#endif
#ifdef SIGTERM
  if(SIG_ERR != old_sigterm_handler)
    (void)signal(SIGTERM, old_sigterm_handler);
#endif
#if defined(SIGBREAK) && defined(WIN32)
  if(SIG_ERR != old_sigbreak_handler)
    (void)signal(SIGBREAK, old_sigbreak_handler);
#endif
#ifdef WIN32
  (void)SetConsoleCtrlHandler(ctrl_event_handler, FALSE);
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
}
