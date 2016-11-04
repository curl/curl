/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/* <DESC>
 * one way to set the necessary OpenSSL locking callbacks if you want to do
 * multi-threaded transfers with HTTPS/FTPS with libcurl built to use OpenSSL.
 * </DESC>
 */
/*
 * This is not a complete stand-alone example.
 *
 * Author: Jeremy Brown
 */

#include <stdio.h>
#include <pthread.h>
#include <openssl/err.h>

#define MUTEX_TYPE       pthread_mutex_t
#define MUTEX_SETUP(x)   pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x)    pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)  pthread_mutex_unlock(&(x))
#define THREAD_ID        pthread_self()


void handle_error(const char *file, int lineno, const char *msg)
{
  fprintf(stderr, "** %s:%d %s\n", file, lineno, msg);
  ERR_print_errors_fp(stderr);
  /* exit(-1); */
}

/* This array will store all of the mutexes available to OpenSSL. */
static MUTEX_TYPE *mutex_buf= NULL;

static void locking_function(int mode, int n, const char * file, int line)
{
  if(mode & CRYPTO_LOCK)
    MUTEX_LOCK(mutex_buf[n]);
  else
    MUTEX_UNLOCK(mutex_buf[n]);
}

static unsigned long id_function(void)
{
  return ((unsigned long)THREAD_ID);
}

int thread_setup(void)
{
  int i;

  mutex_buf = malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
  if(!mutex_buf)
    return 0;
  for(i = 0;  i < CRYPTO_num_locks();  i++)
    MUTEX_SETUP(mutex_buf[i]);
  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(locking_function);
  return 1;
}

int thread_cleanup(void)
{
  int i;

  if(!mutex_buf)
    return 0;
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for(i = 0;  i < CRYPTO_num_locks();  i++)
    MUTEX_CLEANUP(mutex_buf[i]);
  free(mutex_buf);
  mutex_buf = NULL;
  return 1;
}
