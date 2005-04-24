/* src/config-win32.h.  manually created to look like a config.h.  */
/* Define if you have the stricmp function.  */
#define HAVE_STRICMP 1

/* Define to 1 if you want the built-in manual */
#define USE_MANUAL 1

/* Define cpu-machine-OS */
#define OS "i386-pc-win32"

/* Define if you have the <io.h> header file.  */
#define HAVE_IO_H 1

/* Define if you have the <limits.h> header file */
#define HAVE_LIMITS_H 1

/* Define if you have the ftruncate function. */
#define HAVE_FTRUNCATE 1

/* Define if you have the strdup function.  */
#define HAVE_STRDUP 1

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have utime() */
#if !defined(__BORLANDC__)
#define HAVE_UTIME 1

/* Define if you have the <sys/utime.h> header file */
#define HAVE_SYS_UTIME_H 1
#endif

/* Define if you have the <locale.h> header file */
#define HAVE_LOCALE_H 1

/* Define if you have the setlocale() function. */
#define HAVE_SETLOCALE 1

/* Defines set for VS2005 to _not_ decprecate a few functions we use. */
#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE

/*************************************************
 * This section is for compiler specific defines.*
 *************************************************/
/* Borland and MS don't have this */
#if defined(__MINGW32__) || defined(__WATCOMC__) || defined(__LCC__)

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

#else

#endif
