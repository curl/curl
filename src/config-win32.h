/* src/config.h.  Generated automatically by configure.  */
/* Define if you have the strcasecmp function.  */
/*#define HAVE_STRCASECMP 1*/

/* Define if you have the stricmp function.  */
#define HAVE_STRICMP 1

/* Define cpu-machine-OS */
#define OS "win32"

/* Define if you have the <io.h> header file.  */
#define HAVE_IO_H 1
 
/* Define if you have the strdup function.  */
#define HAVE_STRDUP 1

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/*************************************************
 * This section is for compiler specific defines.*
 *************************************************/
#ifdef MINGW32 /* Borland and MS don't have this */

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

#endif
