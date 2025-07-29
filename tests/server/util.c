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
#include "first.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

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
      snprintf(optr, 4, "%%%02x", (unsigned char)*iptr++);
      optr += 3;
    }
  }
  *optr = 0; /* in case no sprintf was used */

  return buf;
}

void loghex(unsigned char *buffer, ssize_t len)
{
  char data[12000];
  ssize_t i;
  unsigned char *ptr = buffer;
  char *optr = data;
  ssize_t width = 0;
  int left = sizeof(data);

  for(i = 0; i < len && (left >= 0); i++) {
    snprintf(optr, left, "%02x", ptr[i]);
    width += 2;
    optr += 2;
    left -= 2;
  }
  if(width)
    logmsg("'%s'", data);
}

void logmsg(const char *msg, ...)
{
  va_list ap;
  char buffer[2048 + 1];
  FILE *logfp;
  struct curltime tv;
  time_t sec;
  struct tm *now;
  char timebuf[50];
  static time_t epoch_offset;
  static int    known_offset;

  if(!serverlogfile) {
    fprintf(stderr, "Serverlogfile not set error\n");
    return;
  }

  tv = curlx_now();
  if(!known_offset) {
    epoch_offset = time(NULL) - tv.tv_sec;
    known_offset = 1;
  }
  sec = epoch_offset + tv.tv_sec;
  /* !checksrc! disable BANNEDFUNC 1 */
  now = localtime(&sec); /* not thread safe but we don't care */

  snprintf(timebuf, sizeof(timebuf), "%02d:%02d:%02d.%06ld",
           (int)now->tm_hour, (int)now->tm_min, (int)now->tm_sec,
           (long)tv.tv_usec);

  va_start(ap, msg);
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
  vsnprintf(buffer, sizeof(buffer), msg, ap);
#ifdef __clang__
#pragma clang diagnostic pop
#endif
  va_end(ap);

  do {
    logfp = fopen(serverlogfile, "ab");
    /* !checksrc! disable ERRNOVAR 1 */
  } while(!logfp && (errno == EINTR));
  if(logfp) {
    fprintf(logfp, "%s %s\n", timebuf, buffer);
    fclose(logfp);
  }
  else {
    int error = errno;
    fprintf(stderr, "fopen() failed with error (%d) %s\n",
            error, strerror(error));
    fprintf(stderr, "Error opening file '%s'\n", serverlogfile);
    fprintf(stderr, "Msg not logged: %s %s\n", timebuf, buffer);
  }
}

unsigned char byteval(char *value)
{
  unsigned long num = strtoul(value, NULL, 10);
  return num & 0xff;
}

#ifdef _WIN32
/* use instead of perror() on generic Windows */
static void win32_perror(const char *msg)
{
  char buf[512];
  int err = SOCKERRNO;
  curlx_winapi_strerror(err, buf, sizeof(buf));
  if(msg)
    fprintf(stderr, "%s: ", msg);
  fprintf(stderr, "%s\n", buf);
}

static void win32_cleanup(void)
{
#ifdef USE_WINSOCK
  WSACleanup();
#endif

  /* flush buffers of all streams regardless of their mode */
  _flushall();
}

int win32_init(void)
{
  curlx_now_init();
#ifdef USE_WINSOCK
  {
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);

    if(err) {
      win32_perror("Winsock init failed");
      logmsg("Error initialising Winsock -- aborting");
      return 1;
    }

    if(LOBYTE(wsaData.wVersion) != LOBYTE(wVersionRequested) ||
       HIBYTE(wsaData.wVersion) != HIBYTE(wVersionRequested) ) {
      WSACleanup();
      win32_perror("Winsock init failed");
      logmsg("No suitable winsock.dll found -- aborting");
      return 1;
    }
  }
#endif  /* USE_WINSOCK */
  atexit(win32_cleanup);
  return 0;
}

/* socket-safe strerror (works on Winsock errors, too) */
const char *sstrerror(int err)
{
  static char buf[512];
  return curlx_winapi_strerror(err, buf, sizeof(buf));
}
#else
#define sstrerror(e) strerror(e)
#endif  /* _WIN32 */

/* fopens the test case file */
FILE *test2fopen(long testno, const char *logdir2)
{
  FILE *stream;
  char filename[256];
  /* first try the alternative, preprocessed, file */
  snprintf(filename, sizeof(filename), "%s/test%ld", logdir2, testno);
  stream = fopen(filename, "rb");
  if(stream)
    return stream;

  /* then try the source version */
  snprintf(filename, sizeof(filename), "%s/data/test%ld", srcpath, testno);
  stream = fopen(filename, "rb");

  return stream;
}

#ifdef _WIN32
#define t_getpid() GetCurrentProcessId()
#else
#define t_getpid() getpid()
#endif

curl_off_t our_getpid(void)
{
  curl_off_t pid = (curl_off_t)t_getpid();
#ifdef _WIN32
  /* store pid + MAX_PID to avoid conflict with Cygwin/msys PIDs, see also:
   * - 2019-01-31: https://cygwin.com/git/?p=newlib-cygwin.git;a=commit;
   *               h=b5e1003722cb14235c4f166be72c09acdffc62ea
   * - 2019-02-02: https://cygwin.com/git/?p=newlib-cygwin.git;a=commit;
   *               h=448cf5aa4b429d5a9cebf92a0da4ab4b5b6d23fe
   * - 2024-12-19: https://cygwin.com/git/?p=newlib-cygwin.git;a=commit;
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
  fprintf(pidfile, "%ld\n", (long)pid);
  fclose(pidfile);
  logmsg("Wrote pid %ld to %s", (long)pid, filename);
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
    /* !checksrc! disable ERRNOVAR 1 */
  } while(!lockfile && ((error = errno) == EINTR));
  if(!lockfile) {
    logmsg("Error creating lock file %s error (%d) %s",
           filename, error, strerror(error));
    return;
  }

  res = fclose(lockfile);
  if(res)
    logmsg("Error closing lock file %s error (%d) %s",
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
    /* !checksrc! disable ERRNOVAR 1 */
  } while(res && ((error = errno) == EINTR));
  if(res)
    logmsg("Error removing lock file %s error (%d) %s",
           filename, error, strerror(error));
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

/* signal handler that will be triggered to indicate that the program
 * should finish its execution in a controlled manner as soon as possible.
 * The first time this is called it will set got_exit_signal to one and
 * store in exit_signal the signal that triggered its execution.
 */
#ifndef UNDER_CE
/*
 * Only call signal-safe functions from the signal handler, as required by
 * the POSIX specification:
 *   https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html
 * Hence, do not call 'logmsg()', and instead use 'open/write/close' to
 * log errors.
 */
static void exit_signal_handler(int signum)
{
  int old_errno = errno;
  if(!serverlogfile) {
    static const char msg[] = "exit_signal_handler: serverlogfile not set\n";
    (void)!write(STDERR_FILENO, msg, sizeof(msg) - 1);
  }
  else {
#ifdef _WIN32
#define OPENMODE S_IREAD | S_IWRITE
#else
#define OPENMODE S_IRUSR | S_IWUSR
#endif
    int fd = open(serverlogfile, O_WRONLY|O_CREAT|O_APPEND, OPENMODE);
    if(fd != -1) {
      static const char msg[] = "exit_signal_handler: called\n";
      (void)!write(fd, msg, sizeof(msg) - 1);
      close(fd);
    }
    else {
      static const char msg[] = "exit_signal_handler: failed opening ";
      (void)!write(STDERR_FILENO, msg, sizeof(msg) - 1);
      (void)!write(STDERR_FILENO, serverlogfile, strlen(serverlogfile));
      (void)!write(STDERR_FILENO, "\n", 1);
    }
  }
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
 * The SIGKILL and SIGTERM signals are not generated under Windows.
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
    win32_perror("RegisterClass failed");
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
    win32_perror("CreateWindowEx failed");
    return (DWORD)-1;
  }

  do {
    ret = GetMessage(&msg, NULL, 0, 0);
    if(ret == -1) {
      win32_perror("GetMessage failed");
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
  (void)restartable;
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
    (void)set_signal(SIGHUP, old_sighup_handler, FALSE);
#endif
#ifdef SIGPIPE
  if(SIG_ERR != old_sigpipe_handler)
    (void)set_signal(SIGPIPE, old_sigpipe_handler, FALSE);
#endif
#ifdef SIGALRM
  if(!keep_sigalrm) {
    if(SIG_ERR != old_sigalrm_handler)
      (void)set_signal(SIGALRM, old_sigalrm_handler, FALSE);
  }
#else
  (void)keep_sigalrm;
#endif
#ifdef SIGINT
  if(SIG_ERR != old_sigint_handler)
    (void)set_signal(SIGINT, old_sigint_handler, FALSE);
#endif
#ifdef SIGTERM
  if(SIG_ERR != old_sigterm_handler)
    (void)set_signal(SIGTERM, old_sigterm_handler, FALSE);
#endif
#if defined(SIGBREAK) && defined(_WIN32)
  if(SIG_ERR != old_sigbreak_handler)
    (void)set_signal(SIGBREAK, old_sigbreak_handler, FALSE);
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
  if(rc && SOCKERRNO == SOCKEADDRINUSE) {
    struct_stat statbuf;
    /* socket already exists. Perhaps it is stale? */
    curl_socket_t unixfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(CURL_SOCKET_BAD == unixfd) {
      logmsg("Failed to create socket at %s (%d) %s",
             unix_socket, SOCKERRNO, sstrerror(SOCKERRNO));
      return -1;
    }
    /* check whether the server is alive */
    rc = connect(unixfd, (struct sockaddr*)sau, sizeof(struct sockaddr_un));
    error = SOCKERRNO;
    sclose(unixfd);
    if(rc && error != SOCKECONNREFUSED) {
      logmsg("Failed to connect to %s (%d) %s",
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
    if(rc) {
      logmsg("Error binding socket, failed to stat %s (%d) %s",
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
    if(rc) {
      logmsg("Error binding socket, failed to unlink %s (%d) %s",
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

curl_socket_t sockdaemon(curl_socket_t sock,
                         unsigned short *listenport,
                         const char *unix_socket,
                         bool bind_only)
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

#ifndef USE_UNIX_SOCKETS
  (void)unix_socket;
#endif

  do {
    attempt++;
    flag = 1;
    rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                    (void *)&flag, sizeof(flag));
    if(rc) {
      error = SOCKERRNO;
      logmsg("setsockopt(SO_REUSEADDR) failed with error (%d) %s",
             error, sstrerror(error));
      if(maxretr) {
        rc = curlx_wait_ms(delay);
        if(rc) {
          /* should not happen */
          error = SOCKERRNO;
          logmsg("curlx_wait_ms() failed with error (%d) %s",
                 error, sstrerror(error));
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
    logmsg("setsockopt(SO_REUSEADDR) failed %d times in %d ms. Error (%d) %s",
           attempt, totdelay, error, strerror(error));
    logmsg("Continuing anyway...");
  }

  /* When the specified listener port is zero, it is actually a
     request to let the system choose a non-zero available port. */

  switch(socket_domain) {
    case AF_INET:
      memset(&listener.sa4, 0, sizeof(listener.sa4));
      listener.sa4.sin_family = AF_INET;
      listener.sa4.sin_addr.s_addr = INADDR_ANY;
      listener.sa4.sin_port = htons(*listenport);
      rc = bind(sock, &listener.sa, sizeof(listener.sa4));
      break;
#ifdef USE_IPV6
    case AF_INET6:
      memset(&listener.sa6, 0, sizeof(listener.sa6));
      listener.sa6.sin6_family = AF_INET6;
      listener.sa6.sin6_addr = in6addr_any;
      listener.sa6.sin6_port = htons(*listenport);
      rc = bind(sock, &listener.sa, sizeof(listener.sa6));
      break;
#endif /* USE_IPV6 */
#ifdef USE_UNIX_SOCKETS
    case AF_UNIX:
      rc = bind_unix_socket(sock, unix_socket, &listener.sau);
      break;
#endif
    default:
      rc = 1;
  }

  if(rc) {
    error = SOCKERRNO;
#ifdef USE_UNIX_SOCKETS
    if(socket_domain == AF_UNIX)
      logmsg("Error binding socket on path %s (%d) %s",
             unix_socket, error, sstrerror(error));
    else
#endif
      logmsg("Error binding socket on port %hu (%d) %s",
             *listenport, error, sstrerror(error));
    sclose(sock);
    return CURL_SOCKET_BAD;
  }

  if(!*listenport
#ifdef USE_UNIX_SOCKETS
     && !unix_socket
#endif
    ) {
    /* The system was supposed to choose a port number, figure out which
       port we actually got and update the listener port value with it. */
    curl_socklen_t la_size;
    srvr_sockaddr_union_t localaddr;
#ifdef USE_IPV6
    if(socket_domain == AF_INET6)
      la_size = sizeof(localaddr.sa6);
    else
#endif
      la_size = sizeof(localaddr.sa4);
    memset(&localaddr.sa, 0, (size_t)la_size);
    if(getsockname(sock, &localaddr.sa, &la_size) < 0) {
      error = SOCKERRNO;
      logmsg("getsockname() failed with error (%d) %s",
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
  if(rc) {
    error = SOCKERRNO;
    logmsg("listen(%ld, 5) failed with error (%d) %s",
           (long)sock, error, sstrerror(error));
    sclose(sock);
    return CURL_SOCKET_BAD;
  }

  return sock;
}
