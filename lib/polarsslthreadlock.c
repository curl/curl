/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010, 2011, Hoi-Ho Chan, <hoiho.chan@gmail.com>
 * Copyright (C) 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <stdio.h>
#include "curl_setup.h"

#ifdef USE_POLARSSL

#if defined(USE_THREADS_POSIX)
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#define MUTEX_TYPE       pthread_mutex_t
#endif /* HAVE_PTHREAD_H */
#endif /* USE_THREADS_POSIX */

#include "polarsslthreadlock.h"

/* number of thread locks */
#define NUMT                    2

/* This array will store all of the mutexes available to PolarSSL. */
static MUTEX_TYPE *mutex_buf = NULL;

int polarsslthreadlock_thread_setup(void)
{
  int i;
  int ret;

  mutex_buf = malloc(NUMT * sizeof(MUTEX_TYPE));
  if (!mutex_buf)
    return 0;     /* error, no number of threads defined */

#ifdef HAVE_PTHREAD_H
  for (i = 0;  i < NUMT;  i++)
  {
    ret = pthread_mutex_init(&mutex_buf[i], NULL);
	if(ret)
	   return 0; /* pthread_mutex_init failed */
  }
#endif /* HAVE_PTHREAD_H */

  return 1; /* OK */
}

int polarsslthreadlock_thread_cleanup(void)
{
  int i;
  int ret;
  
  if (!mutex_buf)
    return 0; /* error, no threads locks defined */

#ifdef HAVE_PTHREAD_H
  for (i = 0; i < NUMT; i++)
  {
    ret = pthread_mutex_destroy(&mutex_buf[i]);
	if(ret)
	   return 0; /* pthread_mutex_destroy failed */
  } 
#endif /* HAVE_PTHREAD_H */
  free(mutex_buf);
  mutex_buf = NULL;

  return 1; /* OK */
}

int polarsslthreadlock_lock_function(int n)
{
  int ret;
#ifdef HAVE_PTHREAD_H
  if(n < NUMT)
  {
    ret = pthread_mutex_lock(&mutex_buf[n]);
	if(ret)
	{
	  DEBUGF(fprintf(stderr, "Error: pthread_mutex_lock failed\n"));
	  return 0; /* pthread_mutex_lock failed */
	}
  } 
#endif /* HAVE_PTHREAD_H */
  return 1; /* OK */
}

int polarsslthreadlock_unlock_function(int n)
{
  int ret;
#ifdef HAVE_PTHREAD_H
  if(n < NUMT)
  {
    ret = pthread_mutex_unlock(&mutex_buf[n]);
	if(ret)
	{
	  DEBUGF(fprintf(stderr, "Error: pthread_mutex_unlock failed\n"));
	  return 0; /* pthread_mutex_unlock failed */
	}
  }
#endif /* HAVE_PTHREAD_H */
  return 1; /* OK */
}

#endif /* USE_POLARSSL */
