#include "test.h"
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

const char *HOSTHEADER = "Host: www.host.foo.com";
const char *JAR = "log/jar506";
#define THREADS 2

void lock(CURL *handle, curl_lock_data data, curl_lock_access access,
          void *useptr );
void unlock(CURL *handle, curl_lock_data data, void *useptr );
struct curl_slist *sethost(struct curl_slist *headers);
void *fire(void *ptr);
char *suburl(char *base, int i);

/* struct containing data of a thread */
struct Tdata {
  CURLSH *share;
  char *url;
};

struct userdata {
  char *text;
  int counter;
};

/* lock callback */
void lock(CURL *handle, curl_lock_data data, curl_lock_access access,
          void *useptr )
{
  const char *what;
  struct userdata *user = (struct userdata *)useptr;

  (void)handle;
  (void)access;

  switch ( data ) {
    case CURL_LOCK_DATA_SHARE:
      what = "share";  
      break;
    case CURL_LOCK_DATA_DNS:
      what = "dns";  
      break;
    case CURL_LOCK_DATA_COOKIE:
      what = "cookie";  
      break;
    default:
      fprintf(stderr, "lock: no such data: %d\n",data);
      return;
  }
  printf("lock:   %-6s <%s>: %d\n", what, user->text, user->counter);
  user->counter++;
}

/* unlock callback */
void unlock(CURL *handle, curl_lock_data data, void *useptr )
{
  const char *what;
  struct userdata *user = (struct userdata *)useptr;
  (void)handle;
  switch ( data ) {
    case CURL_LOCK_DATA_SHARE:
      what = "share";  
      break;
    case CURL_LOCK_DATA_DNS:
      what = "dns";  
      break;
    case CURL_LOCK_DATA_COOKIE:
      what = "cookie";  
      break;
    default:
      fprintf(stderr, "unlock: no such data: %d\n",data);
      return;
  }
  printf("unlock: %-6s <%s>: %d\n", what, user->text, user->counter);
  user->counter++;
}


/* build host entry */
struct curl_slist *sethost(struct curl_slist *headers)
{
  (void)headers;
  return curl_slist_append(NULL, HOSTHEADER );
}


/* the dummy thread function */
void *fire(void *ptr)
{
  CURLcode code;
  struct curl_slist *headers;
  struct Tdata *tdata = (struct Tdata*)ptr;
  CURL *curl = curl_easy_init();
  int i=0;

  headers = sethost(NULL);
  curl_easy_setopt(curl, CURLOPT_VERBOSE,    1);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, (void*)headers);
  curl_easy_setopt(curl, CURLOPT_URL,        (void*)tdata->url);
  printf( "CURLOPT_SHARE\n" );
  curl_easy_setopt(curl, CURLOPT_SHARE, (void*)tdata->share);

  printf( "PERFORM\n" );
  code = curl_easy_perform(curl);
  if( code != CURLE_OK ) {
    fprintf(stderr, "perform url '%s' repeat %d failed, curlcode %d\n",
            tdata->url, i, (int)code);
  }

  printf( "CLEANUP\n" );
  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);

  return NULL;
}


/* build request url */
char *suburl(char *base, int i)
{
  int len = strlen(base);
  char *url = (char *)malloc(len+5);
  if (!url) {
    abort();
  }
  strcpy(url, base);
  strcat(url, "0000");
  url[len+3] = 48+i;
  return url;
}


/* test function */
int test(char *URL)
{
  int res;
  CURLSHcode scode;
  char *url;
  struct Tdata tdata;
  CURL *curl;
  CURLSH *share;
  struct curl_slist *headers;
  int i;
  struct userdata user;

  user.text = (char *)"Pigs in space";
  user.counter = 0;
  
  printf( "GLOBAL_INIT\n" );
  curl_global_init( CURL_GLOBAL_ALL );

  /* prepare share */
  printf( "SHARE_INIT\n" );
  share = curl_share_init();
  curl_share_setopt( share, CURLSHOPT_LOCKFUNC,   lock);
  curl_share_setopt( share, CURLSHOPT_UNLOCKFUNC, unlock);
  curl_share_setopt( share, CURLSHOPT_USERDATA,   &user);
  printf( "CURL_LOCK_DATA_COOKIE\n" );
  curl_share_setopt( share, CURLSHOPT_SHARE,      CURL_LOCK_DATA_COOKIE);
  printf( "CURL_LOCK_DATA_DNS\n" );
  curl_share_setopt( share, CURLSHOPT_SHARE,      CURL_LOCK_DATA_DNS);
  
  res = 0;

  /* start treads */
  for (i=1; i<=THREADS; i++ ) {
    
    /* set thread data */
    tdata.url   = suburl( URL, i ); /* must be freed */
    tdata.share = share;

    /* simulate thread, direct call of "thread" function */
    printf( "*** run %d\n",i );
    fire( &tdata );

    free( tdata.url );

  }


  /* fetch a another one and save cookies */
  printf( "*** run %d\n", i );
  curl = curl_easy_init();

  url = suburl( URL, i );
  headers = sethost( NULL );
  curl_easy_setopt( curl, CURLOPT_HTTPHEADER, (void*)headers );
  curl_easy_setopt( curl, CURLOPT_URL,        url );
  printf( "CURLOPT_SHARE\n" );
  curl_easy_setopt( curl, CURLOPT_SHARE,      share );
  printf( "CURLOPT_COOKIEJAR\n" );
  curl_easy_setopt( curl, CURLOPT_COOKIEJAR,  JAR );

  printf( "PERFORM\n" );
  curl_easy_perform( curl );

  /* try to free share, expect to fail because share is in use*/
  printf( "try SHARE_CLEANUP...\n" );
  scode = curl_share_cleanup( share );
  if ( scode==CURLSHE_OK )
  {
    fprintf(stderr, "curl_share_cleanup succeed but error expected\n");
    share = NULL;
  } else {
    printf( "SHARE_CLEANUP failed, correct\n" );
  }

  /* clean up last handle */
  printf( "CLEANUP\n" );
  curl_easy_cleanup( curl );
  curl_slist_free_all( headers );
  free(url);
  
  
  /* free share */
  printf( "SHARE_CLEANUP\n" );
  scode = curl_share_cleanup( share );
  if ( scode!=CURLSHE_OK )
  {
    fprintf(stderr, "curl_share_cleanup failed, code errno %d\n", scode);
  }
  
  printf( "GLOBAL_CLEANUP\n" );
  curl_global_cleanup();
 
  return res;
}

