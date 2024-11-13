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
 *
 ***************************************************************************/

/*
 * QADRT/QADRTMAIN2 substitution program.
 * This is needed because the IBM-provided QADRTMAIN2 does not
 * properly translate arguments by default or if no locale is provided.
 */

#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <errno.h>
#include <locale.h>

/* Do not use qadrt.h since it defines unneeded static procedures. */
extern void     QadrtInit(void);
extern int      QadrtFreeConversionTable(void);
extern int      QadrtFreeEnviron(void);
extern char *   setlocale_a(int, const char *);


/* The ASCII main program. */
extern int      main_a(int argc, char * * argv);

/* Global values of original EBCDIC arguments. */
int             ebcdic_argc;
char **         ebcdic_argv;


int main(int argc, char **argv)
{
  int i;
  int j;
  iconv_t cd;
  size_t bytecount = 0;
  char *inbuf;
  char *outbuf;
  size_t inbytesleft;
  size_t outbytesleft;
  char dummybuf[128];
  /* To/From codes are 32 byte long strings with
     reserved fields initialized to ZEROs */
  const char tocode[32]   = {"IBMCCSID01208"}; /* Use UTF-8. */
  const char fromcode[32] = {"IBMCCSID000000000010"};

  ebcdic_argc = argc;
  ebcdic_argv = argv;

  /* Build the encoding converter. */
  cd = iconv_open(tocode, fromcode);

  /* Measure the arguments. */
  for(i = 0; i < argc; i++) {
    inbuf = argv[i];
    do {
      inbytesleft = 0;
      outbuf = dummybuf;
      outbytesleft = sizeof(dummybuf);
      j = iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
      bytecount += outbuf - dummybuf;
    } while(j == -1 && errno == E2BIG);

    /* Reset the shift state. */
    iconv(cd, NULL, &inbytesleft, &outbuf, &outbytesleft);
   }

  /* Allocate memory for the ASCII arguments and vector. */
  argv = (char **) malloc((argc + 1) * sizeof(*argv) + bytecount);

  /* Build the vector and convert argument encoding. */
  outbuf = (char *) (argv + argc + 1);
  outbytesleft = bytecount;

  for(i = 0; i < argc; i++) {
    argv[i] = outbuf;
    inbuf = ebcdic_argv[i];
    inbytesleft = 0;
    iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
    iconv(cd, NULL, &inbytesleft, &outbuf, &outbytesleft);
  }

  iconv_close(cd);
  argv[argc] = NULL;

  /* Try setting the locale regardless of QADRT_ENV_LOCALE. */
  setlocale_a(LC_ALL, "");

  /* Call the program. */
  i = main_a(argc, argv);

  /* Clean-up allocated items. */
  free((char *) argv);
  QadrtFreeConversionTable();
  QadrtFreeEnviron();

  /* Terminate. */
  return i;
}
