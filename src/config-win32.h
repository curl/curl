/* src/config-win32.h.  manually created to look like a config.h.  */
/* Define if you have the stricmp function.  */
#define HAVE_STRICMP 1

/* Define cpu-machine-OS */
#define OS "i386-pc-win32"

/* Define if you have the <io.h> header file.  */
#define HAVE_IO_H 1
 
/* Define if you have the <limits.h> header file */
#define HAVE_LIMITS_H 1

/* Define if you have the strdup function.  */
#define HAVE_STRDUP 1

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have utime() */
#define HAVE_UTIME 1

/* Define if you have the <sys/utime.h> header file */
#define HAVE_SYS_UTIME_H 1

/*************************************************
 * This section is for compiler specific defines.*
 *************************************************/
#ifdef MINGW32 /* Borland and MS don't have this */

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

#endif
