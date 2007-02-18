#ifndef __SETUP_ONCE_H
#define __SETUP_ONCE_H

/* $Id$ */

/* Copyright (C) 2004 - 2007 by Daniel Stenberg et al
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  M.I.T. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */


/********************************************************************
 *                              NOTICE                              *
 *                             ========                             *
 *                                                                  *
 *  Content of header files lib/setup_once.h and ares/setup_once.h  *
 *  must be kept in sync. Modify the other one if you change this.  *
 *                                                                  *
 ********************************************************************/


/*
 * Inclusion of common header files.
 */

#include <errno.h>


/*
 * If we have the MSG_NOSIGNAL define, make sure we use
 * it as the fourth argument of function send()
 */

#ifdef HAVE_MSG_NOSIGNAL
#define SEND_4TH_ARG MSG_NOSIGNAL
#else
#define SEND_4TH_ARG 0
#endif 


/*
 * The definitions for the return type and arguments types
 * of functions recv() and send() belong and come from the
 * configuration file. Do not define them in any other place.
 *
 * HAVE_RECV is defined if you have a function named recv()
 * which is used to read incoming data from sockets. If your
 * function has another name then don't define HAVE_RECV.
 *
 * If HAVE_RECV is defined then RECV_TYPE_ARG1, RECV_TYPE_ARG2,
 * RECV_TYPE_ARG3, RECV_TYPE_ARG4 and RECV_TYPE_RETV must also
 * be defined.
 *
 * HAVE_SEND is defined if you have a function named send()
 * which is used to write outgoing data on a connected socket.
 * If yours has another name then don't define HAVE_SEND.
 *
 * If HAVE_SEND is defined then SEND_TYPE_ARG1, SEND_QUAL_ARG2,
 * SEND_TYPE_ARG2, SEND_TYPE_ARG3, SEND_TYPE_ARG4 and
 * SEND_TYPE_RETV must also be defined.
 */

#ifdef HAVE_RECV
#if !defined(RECV_TYPE_ARG1) || \
    !defined(RECV_TYPE_ARG2) || \
    !defined(RECV_TYPE_ARG3) || \
    !defined(RECV_TYPE_ARG4) || \
    !defined(RECV_TYPE_RETV)
  /* */
  Error Missing_definition_of_return_and_arguments_types_of_recv
  /* */
#else
#define sread(x,y,z) (ssize_t)recv((RECV_TYPE_ARG1)(x), \
                                   (RECV_TYPE_ARG2)(y), \
                                   (RECV_TYPE_ARG3)(z), \
                                   (RECV_TYPE_ARG4)(0))
#endif
#else /* HAVE_RECV */
#ifndef sread
  /* */
  Error Missing_definition_of_macro_sread
  /* */
#endif
#endif /* HAVE_RECV */

#ifdef HAVE_SEND
#if !defined(SEND_TYPE_ARG1) || \
    !defined(SEND_QUAL_ARG2) || \
    !defined(SEND_TYPE_ARG2) || \
    !defined(SEND_TYPE_ARG3) || \
    !defined(SEND_TYPE_ARG4) || \
    !defined(SEND_TYPE_RETV)
  /* */
  Error Missing_definition_of_return_and_arguments_types_of_send
  /* */
#else
#define swrite(x,y,z) (ssize_t)send((SEND_TYPE_ARG1)(x), \
                                    (SEND_TYPE_ARG2)(y), \
                                    (SEND_TYPE_ARG3)(z), \
                                    (SEND_TYPE_ARG4)(SEND_4TH_ARG))
#endif
#else /* HAVE_SEND */
#ifndef swrite
  /* */
  Error Missing_definition_of_macro_swrite
  /* */
#endif
#endif /* HAVE_SEND */


/*
 * Uppercase macro versions of ANSI/ISO is*() functions/macros which 
 * avoid negative number inputs with argument byte codes > 127.
 */

#define ISSPACE(x)  (isspace((int)  ((unsigned char)x)))
#define ISDIGIT(x)  (isdigit((int)  ((unsigned char)x)))
#define ISALNUM(x)  (isalnum((int)  ((unsigned char)x)))
#define ISXDIGIT(x) (isxdigit((int) ((unsigned char)x)))
#define ISGRAPH(x)  (isgraph((int)  ((unsigned char)x)))
#define ISALPHA(x)  (isalpha((int)  ((unsigned char)x)))
#define ISPRINT(x)  (isprint((int)  ((unsigned char)x)))
#define ISUPPER(x)  (isupper((int)  ((unsigned char)x)))
#define ISLOWER(x)  (islower((int)  ((unsigned char)x)))

#define ISBLANK(x)  (int)((((unsigned char)x) == ' ') || \
                          (((unsigned char)x) == '\t'))


/*
 * Typedef to 'int' if sig_atomic_t is not an available 'typedefed' type.
 */

#ifndef HAVE_SIG_ATOMIC_T
typedef int sig_atomic_t;
#define HAVE_SIG_ATOMIC_T
#endif


/*
 * Default return type for signal handlers.
 */

#ifndef RETSIGTYPE
#define RETSIGTYPE void
#endif


/*
 * Macro used to include code only in debug builds.
 */

#ifdef CURLDEBUG
#define DEBUGF(X) X
#else
#define DEBUGF(X) do { } while (0)
#endif


/*
 * Macro SOCKERRNO / SET_SOCKERRNO() returns / sets the *socket-related* errno
 * (or equivalent) on this platform to hide platform details to code using it.
 */

#ifdef USE_WINSOCK
#define SOCKERRNO         ((int)WSAGetLastError())
#define SET_SOCKERRNO(x)  (WSASetLastError((int)(x)))
#else
#define SOCKERRNO         (errno)
#define SET_SOCKERRNO(x)  (errno = (x))
#endif


/*
 * Macro ERRNO / SET_ERRNO() returns / sets the NOT *socket-related* errno
 * (or equivalent) on this platform to hide platform details to code using it.
 */

#ifdef WIN32
#define ERRNO         ((int)GetLastError())
#define SET_ERRNO(x)  (SetLastError((DWORD)(x)))
#else
#define ERRNO         (errno)
#define SET_ERRNO(x)  (errno = (x))
#endif


/*
 * Portable error number symbolic names defined to Winsock error codes.
 */

#ifdef USE_WINSOCK
#define EWOULDBLOCK      WSAEWOULDBLOCK
#define EINPROGRESS      WSAEINPROGRESS
#define EALREADY         WSAEALREADY
#define ENOTSOCK         WSAENOTSOCK
#define EDESTADDRREQ     WSAEDESTADDRREQ
#define EMSGSIZE         WSAEMSGSIZE
#define EPROTOTYPE       WSAEPROTOTYPE
#define ENOPROTOOPT      WSAENOPROTOOPT
#define EPROTONOSUPPORT  WSAEPROTONOSUPPORT
#define ESOCKTNOSUPPORT  WSAESOCKTNOSUPPORT
#define EOPNOTSUPP       WSAEOPNOTSUPP
#define EPFNOSUPPORT     WSAEPFNOSUPPORT
#define EAFNOSUPPORT     WSAEAFNOSUPPORT
#define EADDRINUSE       WSAEADDRINUSE
#define EADDRNOTAVAIL    WSAEADDRNOTAVAIL
#define ENETDOWN         WSAENETDOWN
#define ENETUNREACH      WSAENETUNREACH
#define ENETRESET        WSAENETRESET
#define ECONNABORTED     WSAECONNABORTED
#define ECONNRESET       WSAECONNRESET
#define ENOBUFS          WSAENOBUFS
#define EISCONN          WSAEISCONN
#define ENOTCONN         WSAENOTCONN
#define ESHUTDOWN        WSAESHUTDOWN
#define ETOOMANYREFS     WSAETOOMANYREFS
#define ETIMEDOUT        WSAETIMEDOUT
#define ECONNREFUSED     WSAECONNREFUSED
#define ELOOP            WSAELOOP
#ifndef ENAMETOOLONG     /* possible previous definition in errno.h */
#define ENAMETOOLONG     WSAENAMETOOLONG
#endif
#define EHOSTDOWN        WSAEHOSTDOWN
#define EHOSTUNREACH     WSAEHOSTUNREACH
#ifndef ENOTEMPTY        /* possible previous definition in errno.h */
#define ENOTEMPTY        WSAENOTEMPTY
#endif
#define EPROCLIM         WSAEPROCLIM
#define EUSERS           WSAEUSERS
#define EDQUOT           WSAEDQUOT
#define ESTALE           WSAESTALE
#define EREMOTE          WSAEREMOTE
#endif


#endif /* __SETUP_ONCE_H */

