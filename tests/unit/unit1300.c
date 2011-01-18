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

static CURLcode unit_setup( void )
{
  llist = Curl_llist_alloc( test_curl_llist_dtor );
  if (!llist)
    return CURLE_OUT_OF_MEMORY;
  return CURLE_OK;
}

static void unit_stop( void )
{
  Curl_llist_destroy( llist, NULL );
}

UNITTEST_START
  int unusedData_case1 = 1;
  int unusedData_case2 = 2;
  int unusedData_case3 = 3;

  int curlErrCode = 0;

  fail_unless( llist->size == 0 , "list initial size should be zero" );
  fail_unless( llist->head == NULL , "list head should initiate to NULL" );
  fail_unless( llist->tail == NULL , "list tail should intiate to NULL" );
  fail_unless( llist->dtor == test_curl_llist_dtor ,
               "list dtor shold initiate to test_curl_llist_dtor" );

  /**
   * testing Curl_llist_insert_next
   * case 1:
   * list is empty
   * @assumptions:
   * 1: list size will be 1
   * 2: list head will hold the data "unusedData_case1"
   * 3: list tail will be the same as list head
   */

  curlErrCode = Curl_llist_insert_next(llist, llist->head, &unusedData_case1);
  if( curlErrCode == 1 ) {
    fail_unless( Curl_llist_count( llist ) == 1 ,
                 "List size should be 1 after adding a new element" );
    /*test that the list head data holds my unusedData */
    fail_unless( llist->head->ptr == &unusedData_case1 ,
                 "List size should be 1 after adding a new element" );
    /*same goes for the list tail */
    fail_unless( llist->tail == llist->head ,
                 "List size should be 1 after adding a new element" );

    /**
     * testing Curl_llist_insert_next
     * case 2:
     * list has 1 element, adding one element after the head
     * @assumptions:
     * 1: the element next to head should be our newly created element
     * 2: the list tail should be our newly created element
     */

    curlErrCode = Curl_llist_insert_next(llist, llist->head ,
                                         &unusedData_case3 );
    if( curlErrCode == 1 ) {
      fail_unless(llist->head->next->ptr == &unusedData_case3 ,
                  "the node next to head is not getting set correctly" );
      fail_unless(llist->tail->ptr == &unusedData_case3,
                  "the list tail is not getting set correctly");
    }
    else {
      printf("skipping Curl_llist_insert_next as a non "
             "success error code was returned\n" );
    }

    /**
     * testing Curl_llist_insert_next
     * case 3:
     * list has >1 element, adding one element after "NULL"
     * @assumptions:
     * 1: the element next to head should be our newly created element
     * 2: the list tail should different from newly created element
     */

    curlErrCode = Curl_llist_insert_next(llist, llist->head,
                                         &unusedData_case2);
    if( curlErrCode == 1 ) {
      fail_unless(llist->head->next->ptr == &unusedData_case2,
                  "the node next to head is not getting set correctly" );
      //better safe than sorry, check that the tail isn't corrupted
      fail_unless(llist->tail->ptr != &unusedData_case2,
                  "the list tail is not getting set correctly" );
    }
    else {
      printf("skipping Curl_llist_insert_next as a non "
             "success error code was returned\n" );
    }

  }
  else {
    printf("skipping Curl_llist_insert_next as a non "
           "success error code was returned\n" );
  }

UNITTEST_STOP
