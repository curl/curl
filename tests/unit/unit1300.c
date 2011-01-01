#include <stdlib.h>
#include "curl_config.h"
#include "setup.h"

#include "llist.h"
#include "curlcheck.h"

struct curl_llist *llist;

static void test_curl_llist_dtor(void *key , void *value)
{
  /* used by the llist API, does nothing here */
  (void)key;
  (void)value;
}

static void unit_setup( void )
{
  llist = Curl_llist_alloc( test_curl_llist_dtor );
}

static void unit_stop( void )
{
  Curl_llist_destroy( llist, NULL );
}

UNITTEST_START

  fail_unless( llist->size == 0 , "list initial size should be zero" );
  fail_unless( llist->head == NULL , "list head should initiate to NULL" );
  fail_unless( llist->tail == NULL , "list tail should intiate to NULL" );
  fail_unless( llist->dtor == test_curl_llist_dtor , "list dtor shold initiate to test_curl_llist_dtor" );

UNITTEST_STOP
