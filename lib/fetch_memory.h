#ifndef HEADER_FETCH_MEMORY_H
#define HEADER_FETCH_MEMORY_H
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

/*
 * Nasty internal details ahead...
 *
 * File fetch_memory.h must be included by _all_ *.c source files
 * that use memory related functions strdup, malloc, calloc, realloc
 * or free, and given source file is used to build libfetch library.
 * It should be included immediately before memdebug.h as the last files
 * included to avoid undesired interaction with other memory function
 * headers in dependent libraries.
 *
 * There is nearly no exception to above rule. All libfetch source
 * files in 'lib' subdirectory as well as those living deep inside
 * 'packages' subdirectories and linked together in order to build
 * libfetch library shall follow it.
 *
 * File lib/strdup.c is an exception, given that it provides a strdup
 * clone implementation while using malloc. Extra care needed inside
 * this one.
 *
 * The need for fetch_memory.h inclusion is due to libfetch's feature
 * of allowing library user to provide memory replacement functions,
 * memory callbacks, at runtime with fetch_global_init_mem()
 *
 * Any *.c source file used to build libfetch library that does not
 * include fetch_memory.h and uses any memory function of the five
 * mentioned above will compile without any indication, but it will
 * trigger weird memory related issues at runtime.
 *
 */

#ifdef HEADER_FETCH_MEMDEBUG_H
/* cleanup after memdebug.h */

#ifdef MEMDEBUG_NODEFINES
#ifdef FETCHDEBUG

#undef strdup
#undef malloc
#undef calloc
#undef realloc
#undef free
#undef send
#undef recv

#ifdef _WIN32
#ifdef UNICODE
#undef wcsdup
#undef _wcsdup
#undef _tcsdup
#else
#undef _tcsdup
#endif
#endif

#undef socket
#undef accept
#ifdef HAVE_SOCKETPAIR
#undef socketpair
#endif

#ifndef FETCH_NO_GETADDRINFO_OVERRIDE
#ifdef HAVE_GETADDRINFO
#if defined(getaddrinfo) && defined(__osf__)
#undef ogetaddrinfo
#else
#undef getaddrinfo
#endif
#endif /* HAVE_GETADDRINFO */

#ifdef HAVE_FREEADDRINFO
#undef freeaddrinfo
#endif /* HAVE_FREEADDRINFO */
#endif /* !FETCH_NO_GETADDRINFO_OVERRIDE */

/* sclose is probably already defined, redefine it! */
#undef sclose
#undef fopen
#undef fdopen
#undef fclose

#endif /* MEMDEBUG_NODEFINES */
#endif /* FETCHDEBUG */

#undef HEADER_FETCH_MEMDEBUG_H
#endif /* HEADER_FETCH_MEMDEBUG_H */

/*
** Following section applies even when FETCHDEBUG is not defined.
*/

#undef fake_sclose

#ifndef FETCH_DID_MEMORY_FUNC_TYPEDEFS /* only if not already done */
/*
 * The following memory function replacement typedef's are COPIED from
 * fetch/fetch.h and MUST match the originals. We copy them to avoid having to
 * include fetch/fetch.h here. We avoid that include since it includes stdio.h
 * and other headers that may get messed up with defines done here.
 */
typedef void *(*fetch_malloc_callback)(size_t size);
typedef void (*fetch_free_callback)(void *ptr);
typedef void *(*fetch_realloc_callback)(void *ptr, size_t size);
typedef char *(*fetch_strdup_callback)(const char *str);
typedef void *(*fetch_calloc_callback)(size_t nmemb, size_t size);
#define FETCH_DID_MEMORY_FUNC_TYPEDEFS
#endif

extern fetch_malloc_callback Fetch_cmalloc;
extern fetch_free_callback Fetch_cfree;
extern fetch_realloc_callback Fetch_crealloc;
extern fetch_strdup_callback Fetch_cstrdup;
extern fetch_calloc_callback Fetch_ccalloc;
#if defined(_WIN32) && defined(UNICODE)
extern fetch_wcsdup_callback Fetch_cwcsdup;
#endif

#ifndef FETCHDEBUG

/*
 * libfetch's 'memory tracking' system defines strdup, malloc, calloc,
 * realloc and free, along with others, in memdebug.h in a different
 * way although still using memory callbacks forward declared above.
 * When using the 'memory tracking' system (FETCHDEBUG defined) we do
 * not define here the five memory functions given that definitions
 * from memdebug.h are the ones that shall be used.
 */

#undef strdup
#define strdup(ptr) Fetch_cstrdup(ptr)
#undef malloc
#define malloc(size) Fetch_cmalloc(size)
#undef calloc
#define calloc(nbelem, size) Fetch_ccalloc(nbelem, size)
#undef realloc
#define realloc(ptr, size) Fetch_crealloc(ptr, size)
#undef free
#define free(ptr) Fetch_cfree(ptr)

#ifdef _WIN32
#ifdef UNICODE
#undef wcsdup
#define wcsdup(ptr) Fetch_cwcsdup(ptr)
#undef _wcsdup
#define _wcsdup(ptr) Fetch_cwcsdup(ptr)
#undef _tcsdup
#define _tcsdup(ptr) Fetch_cwcsdup(ptr)
#else
#undef _tcsdup
#define _tcsdup(ptr) Fetch_cstrdup(ptr)
#endif
#endif

#endif /* FETCHDEBUG */
#endif /* HEADER_FETCH_MEMORY_H */
