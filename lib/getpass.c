/* ============================================================================
 * Copyright (C) 1998 Angus Mackay. All rights reserved; 
 *
 * Redistribution and use are freely permitted provided that:
 *
 *   1) This header remain in tact.
 *   2) The prototype for getpass is not changed from:
 *         char *getpass(const char *prompt)
 *   3) This source code is not used outside of this(getpass.c) file.
 *   3) Any changes to this(getpass.c) source code are made publicly available.
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
 *
 * Contributor(s):
 *   Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 */

#ifndef WIN32
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#ifdef HAVE_TERMIOS_H
#  if !defined(HAVE_TCGETATTR) && !defined(HAVE_TCSETATTR) 
#    undef HAVE_TERMIOS_H
#  endif
#endif

#define INPUT_BUFFER 128

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

/* no perror? make an fprintf! */
#ifndef HAVE_PERROR
#  define perror(x) fprintf(stderr, "Error in: %s\n", x)
#endif

char *getpass(const char *prompt)
{
  FILE *infp;
  FILE *outfp;
  static char buf[INPUT_BUFFER];
  RETSIGTYPE (*sigint)();
  RETSIGTYPE (*sigtstp)();
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
  sigtstp = signal(SIGTSTP, SIG_IGN);

  if( (infp=fopen("/dev/tty", "r")) == NULL )
  {
    infp = stdin;
  }
  if( (outfp=fopen("/dev/tty", "w")) == NULL )
  {
    outfp = stderr;
  }
  infd = fileno(infp);
  outfd = fileno(outfp);

  /* dissable echo */
#ifdef HAVE_TERMIOS_H
  if(tcgetattr(outfd, &orig) != 0)
  {
    perror("tcgetattr");
  }
  noecho = orig;
  noecho.c_lflag &= ~ECHO;
  if(tcsetattr(outfd, TCSANOW, &noecho) != 0)
  {
    perror("tcgetattr");
  }
#else
#  ifdef HAVE_TERMIO_H
  if(ioctl(outfd, TCGETA, &orig) != 0)
  {
    perror("ioctl");
  }
  noecho = orig;
  noecho.c_lflag &= ~ECHO;
  if(ioctl(outfd, TCSETA, &noecho) != 0)
  {
    perror("ioctl");
  }
#  else
#  endif
#endif

  fputs(prompt, outfp);
  fflush(outfp);

  bytes_read=read(infd, buf, INPUT_BUFFER);
  buf[bytes_read > 0 ? (bytes_read -1) : 0] = '\0';

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
   * user types more than INPUT_BUFFER
   */
#ifdef HAVE_TERMIOS_H
  if(tcsetattr(outfd, TCSAFLUSH, &orig) != 0)
  {
    perror("tcgetattr");
  }
#else
#  ifdef HAVE_TERMIO_H
  if(ioctl(outfd, TCSETA, &orig) != 0)
  {
    perror("ioctl");
  }
#  else
#  endif
#endif
  
  signal(SIGINT, sigint);
  signal(SIGTSTP, sigtstp);

  return(buf);
}
#else
#include <stdio.h>
char *getpass(const char *prompt)
{
	static char password[80];
	printf(prompt);
	gets(password);
	return password;
}
#endif /* don't do anything if WIN32 */
