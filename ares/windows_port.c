#include "setup.h"

/* $Id$ */

/* only do the following on windows
 */
#if (defined(WIN32) || defined(WATT32)) && !defined(MSDOS)
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>

#ifdef WATT32
#include <sys/socket.h>
#else
#include "nameser.h"
#endif
#include "ares.h"
#include "ares_private.h"

#ifdef __WATCOMC__
/*
 * Watcom needs a DllMain() in order to initialise the clib startup code.
 */
BOOL
WINAPI DllMain (HINSTANCE hnd, DWORD reason, LPVOID reserved)
{
  (void) hnd;
  (void) reason;
  (void) reserved;
  return (TRUE);
}
#endif


#endif /* WIN32 builds only */
