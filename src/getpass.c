/* ============================================================================
 *
 * Redistribution and use are freely permitted provided that:
 *
 *   1) This header remain in tact.
 *   2) The prototypes for getpass and getpass_r are not changed from:
 *         char *getpass(const char *prompt)
 *         char *getpass_r(const char *prompt, char* buffer, int buflen)
 *   3) This source code is not used outside of this(getpass.c) file.
 *   4) Any changes to this(getpass.c) source code are made publicly available.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ============================================================================
 *
 * $Id$
 *
 * The spirit of this license is to allow use of this source code in any
 * project be it open or closed but still encourage the use of the open,
 * library based equivilents.
 *
 * Author(s):
 *   Angus Mackay <amackay@gus.ml.org>
 *   Daniel Stenberg <daniel@haxx.se>
 */

#include "setup.h" /* setup.h is required for read() prototype */

#ifndef HAVE_GETPASS_R

#include "getpass.h"

#ifndef WIN32
#ifdef	VMS
#include <stdio.h>
#include <string.h>
#include descrip
#include starlet
#include iodef
/* #include iosbdef */
char *getpass_r(const char *prompt, char *buffer, size_t buflen)
{
  long sts;
  short chan;
  struct _iosb iosb;
  /* MSK, 23-JAN-2004, iosbdef.h wasn't in VAX V7.2 or CC 6.4  */
  /* distribution so I created this.  May revert back later to */
  /* struct _iosb iosb;                                        */
  struct _iosb
     {
     short int iosb$w_status; /* status     */
     short int iosb$w_bcnt;   /* byte count */
     int       unused;        /* unused     */
     } iosb;

  $DESCRIPTOR(ttdesc, "TT");

  buffer[0]='\0';
  sts = sys$assign(&ttdesc, &chan,0,0);
  if (sts & 1) {
    sts = sys$qiow(0, chan,
                   IO$_READPROMPT | IO$M_NOECHO,
                   &iosb, 0, 0, buffer, buflen, 0, 0,
                   prompt, strlen(prompt));

    if((sts & 1) && (iosb.iosb$w_status&1))
      buffer[iosb.iosb$w_bcnt] = '\0';

    sts = sys$dassgn(chan);
  }
  return buffer; /* we always return success */
}
#else /* VMS */
#ifdef HAVE_TERMIOS_H
#  if !defined(HAVE_TCGETATTR) && !defined(HAVE_TCSETATTR) 
#    undef HAVE_TERMIOS_H
#  endif
#endif

#ifndef RETSIGTYPE
#  define RETSIGTYPE void
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <signal.h>
#ifdef HAVE_TERMIOS_H
#  include <termios.h>
#else
#  ifdef HAVE_TERMIO_H
#  include <termio.h>
#  else
#  endif
#endif

/* The last #include file should be: */
#if defined(CURLDEBUG) && defined(CURLTOOLDEBUG)
#include "memdebug.h"
#endif

char *getpass_r(const char *prompt, char *buffer, size_t buflen)
{
  FILE *infp;
  char infp_fclose = 0;
  FILE *outfp;
  RETSIGTYPE (*sigint)(int);
#ifdef SIGTSTP
  RETSIGTYPE (*sigtstp)(int);
#endif
  size_t bytes_read;
  int infd;
  int outfd;
#ifdef HAVE_TERMIOS_H
  struct termios orig;
  struct termios noecho;
#else
#  ifdef HAVE_TERMIO_H
  struct termio orig;
  struct termio noecho;  
#  else
#  endif
#endif

  sigint = signal(SIGINT, SIG_IGN);
#ifdef SIGTSTP
  sigtstp = signal(SIGTSTP, SIG_IGN);
#endif

  infp=fopen("/dev/tty", "r");
  if( NULL == infp )
    infp = stdin;
  else
    infp_fclose = 1;

  outfp = stderr;

  infd = fileno(infp);
  outfd = fileno(outfp);

  /* dissable echo */
#ifdef HAVE_TERMIOS_H
  tcgetattr(outfd, &orig);

  noecho = orig;
  noecho.c_lflag &= ~ECHO;
  tcsetattr(outfd, TCSANOW, &noecho);
#else
#  ifdef HAVE_TERMIO_H
  ioctl(outfd, TCGETA, &orig);
  noecho = orig;
  noecho.c_lflag &= ~ECHO;
  ioctl(outfd, TCSETA, &noecho);
#  else
#  endif
#endif

  fputs(prompt, outfp);
  fflush(outfp);

  bytes_read=read(infd, buffer, buflen);
  buffer[bytes_read > 0 ? (bytes_read -1) : 0] = '\0';

  /* print a new line if needed */
#ifdef HAVE_TERMIOS_H
  fputs("\n", outfp);
#else
#  ifdef HAVE_TERMIO_H
  fputs("\n", outfp);
#  else
#  endif
#endif

  /*
   * reset term charectaristics, use TCSAFLUSH incase the
   * user types more than buflen
   */
#ifdef HAVE_TERMIOS_H
  tcsetattr(outfd, TCSAFLUSH, &orig);
#else
#  ifdef HAVE_TERMIO_H
  ioctl(outfd, TCSETA, &orig);
#  else
#  endif
#endif
  
  signal(SIGINT, sigint);
#ifdef SIGTSTP
  signal(SIGTSTP, sigtstp);
#endif

  if(infp_fclose)
    fclose(infp);

  return buffer; /* we always return success */
}
#endif /* VMS */
#else /* WIN32 */
#include <stdio.h>
#include <conio.h>
char *getpass_r(const char *prompt, char *buffer, size_t buflen)
{
  size_t i;
  printf("%s", prompt);
 
  for(i=0; i<buflen; i++) {
    buffer[i] = getch();
    if ( buffer[i] == '\r' ) {
      buffer[i] = 0;
      break;
    }
    else
      if ( buffer[i] == '\b')
        /* remove this letter and if this is not the first key, remove the
           previous one as well */
        i = i - (i>=1?2:1);
  }
  /* if user didn't hit ENTER, terminate buffer */
  if (i==buflen)
    buffer[buflen-1]=0;

  return buffer; /* we always return success */
}
#endif

#endif /* ifndef HAVE_GETPASS_R */

#if 0
/* for consistensy, here's the old-style function: */
char *getpass(const char *prompt)
{
  static char buf[256];
  return getpass_r(prompt, buf, sizeof(buf));
}
#endif
