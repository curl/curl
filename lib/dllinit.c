/* dllinit.c -- Portable DLL initialization. 
   Copyright (C) 1998, 1999 Free Software Foundation, Inc.
   Contributed by Mumit Khan (khan@xraylith.wisc.edu).

   I've used DllMain as the DLL "main" since that's the most common 
   usage. MSVC and Mingw32 both default to DllMain as the standard
   callback from the linker entry point. Cygwin, as of b20.1, also
   uses DllMain as the default callback from the entry point.

   The real entry point is typically always defined by the runtime 
   library, and usually never overridden by (casual) user. What you can 
   override however is the callback routine that the entry point calls, 
   and this file provides such a callback function, DllMain.

   Mingw32: The default entry point for mingw32 is DllMainCRTStartup
   which is defined in libmingw32.a This in turn calls DllMain which is
   defined here. If not defined, there is a stub in libmingw32.a which
   does nothing.

   Cygwin: The default entry point for Cygwin b20.1 or newer is
   __cygwin_dll_entry which is defined in libcygwin.a. This in turn
   calls the routine DllMain. If not defined, there is a stub in
   libcygwin.a which does nothing. 

   MSVC: MSVC runtime calls DllMain, just like Mingw32.

   Summary: If you need to do anything special in DllMain, just add it
   here. Otherwise, the default setup should be just fine for 99%+ of
   the time. I strongly suggest that you *not* change the entry point,
   but rather change DllMain as appropriate.

 */


#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#include <stdio.h>

BOOL APIENTRY DllMain (HINSTANCE hInst, DWORD reason, 
                       LPVOID reserved /* Not used. */ );

/*
 *----------------------------------------------------------------------
 *
 * DllMain --
 *
 *	This routine is called by the Mingw32, Cygwin32 or VC++ C run 
 *	time library init code, or the Borland DllEntryPoint routine. It 
 *	is responsible for initializing various dynamically loaded 
 *	libraries.
 *
 * Results:
 *      TRUE on sucess, FALSE on failure.
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */
BOOL APIENTRY
DllMain (
	 HINSTANCE hInst /* Library instance handle. */ ,
	 DWORD reason /* Reason this function is being called. */ ,
	 LPVOID reserved /* Not used. */ )
{

  switch (reason)
    {
    case DLL_PROCESS_ATTACH:
      break;

    case DLL_PROCESS_DETACH:
      break;

    case DLL_THREAD_ATTACH:
      break;

    case DLL_THREAD_DETACH:
      break;
    }
  return TRUE;
}
