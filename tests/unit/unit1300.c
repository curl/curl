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
#include "curlcheck.h"

#include "llist.h"

static struct curl_llist *llist;

static struct curl_llist *llist_destination;

static void test_curl_llist_dtor(void *key, void *value)
{
  /* used by the llist API, does nothing here */
  (void)key;
  (void)value;
}

static CURLcode unit_setup(void)
{
  llist = Curl_llist_alloc(test_curl_llist_dtor);
  if(!llist)
    return CURLE_OUT_OF_MEMORY;
  llist_destination = Curl_llist_alloc(test_curl_llist_dtor);
  if(!llist_destination) {
    Curl_llist_destroy(llist, NULL);
    return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}

static void unit_stop(void)
{
  Curl_llist_destroy(llist, NULL);
  Curl_llist_destroy(llist_destination, NULL);
}

UNITTEST_START
  int unusedData_case1 = 1;
  int unusedData_case2 = 2;
  int unusedData_case3 = 3;
  struct curl_llist_element *head;
  struct curl_llist_element *element_next;
  struct curl_llist_element *element_prev;
  struct curl_llist_element *to_remove;
  size_t llist_size = Curl_llist_count(llist);
  int curlErrCode = 0;

  /**
   * testing llist_init
   * case 1:
   * list initiation
   * @assumptions:
   * 1: list size will be 0
   * 2: list head will be NULL
   * 3: list tail will be NULL
   * 4: list dtor will be NULL
  */

  fail_unless(llist->size == 0, "list initial size should be zero");
  fail_unless(llist->head == NULL, "list head should initiate to NULL");
  fail_unless(llist->tail == NULL, "list tail should intiate to NULL");
  fail_unless(llist->dtor == test_curl_llist_dtor,
               "list dtor shold initiate to test_curl_llist_dtor");

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
  if(curlErrCode == 1) {
    fail_unless(Curl_llist_count(llist) == 1,
                 "List size should be 1 after adding a new element");
    /*test that the list head data holds my unusedData */
    fail_unless(llist->head->ptr == &unusedData_case1,
                 "List size should be 1 after adding a new element");
    /*same goes for the list tail */
    fail_unless(llist->tail == llist->head,
                 "List size should be 1 after adding a new element");

    /**
     * testing Curl_llist_insert_next
     * case 2:
     * list has 1 element, adding one element after the head
     * @assumptions:
     * 1: the element next to head should be our newly created element
     * 2: the list tail should be our newly created element
     */

    curlErrCode = Curl_llist_insert_next(llist, llist->head,
                                         &unusedData_case3);
    if(curlErrCode == 1) {
      fail_unless(llist->head->next->ptr == &unusedData_case3,
                  "the node next to head is not getting set correctly");
      fail_unless(llist->tail->ptr == &unusedData_case3,
                  "the list tail is not getting set correctly");
    }
    else {
      printf("skipping Curl_llist_insert_next as a non "
             "success error code was returned\n");
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
    if(curlErrCode == 1) {
      fail_unless(llist->head->next->ptr == &unusedData_case2,
                  "the node next to head is not getting set correctly");
      /* better safe than sorry, check that the tail isn't corrupted */
      fail_unless(llist->tail->ptr != &unusedData_case2,
                  "the list tail is not getting set correctly");
    }
    else {
      printf("skipping Curl_llist_insert_next as a non "
             "success error code was returned\n");
    }

  }
  else {
    printf("skipping Curl_llist_insert_next as a non "
           "success error code was returned\n");
  }

  /* unit tests for Curl_llist_remove */

  /**
   * case 1:
   * list has >1 element, removing head
   * @assumptions:
   * 1: list size will be decremented by one
   * 2: head will be the head->next
   * 3: "new" head's previous will be NULL
   */

  head=llist->head;
  abort_unless(head, "llist->head is NULL");
  element_next = head->next;
  llist_size = Curl_llist_count(llist);

  Curl_llist_remove(llist, llist->head, NULL);

  fail_unless(Curl_llist_count(llist) ==  (llist_size-1),
               "llist size not decremented as expected");
  fail_unless(llist->head == element_next,
               "llist new head not modified properly");
  abort_unless(llist->head, "llist->head is NULL");
  fail_unless(llist->head->prev == NULL,
              "new head previous not set to null");

  /**
   * case 2:
   * removing non head element, with list having >=2 elements
   * @setup:
   * 1: insert another element to the list to make element >=2
   * @assumptions:
   * 1: list size will be decremented by one ; tested
   * 2: element->previous->next will be element->next
   * 3: element->next->previous will be element->previous
   */
  Curl_llist_insert_next(llist, llist->head, &unusedData_case3);
  llist_size = Curl_llist_count(llist);
  to_remove = llist->head->next;
  abort_unless(to_remove, "to_remove is NULL");
  element_next = to_remove->next;
  element_prev = to_remove->prev;
  Curl_llist_remove(llist, to_remove, NULL);
  fail_unless(element_prev->next == element_next,
              "element previous->next is not being adjusted");
  abort_unless(element_next, "element_next is NULL");
  fail_unless(element_next->prev == element_prev,
              "element next->previous is not being adjusted");

  /**
   * case 3:
   * removing the tail with list having >=1 element
   * @assumptions
   * 1: list size will be decremented by one ;tested
   * 2: element->previous->next will be element->next ;tested
   * 3: element->next->previous will be element->previous ;tested
   * 4: list->tail will be tail->previous
   */

  to_remove = llist->tail;
  element_prev = to_remove->prev;
  Curl_llist_remove(llist, to_remove, NULL);
  fail_unless(llist->tail == element_prev,
              "llist tail is not being adjusted when removing tail");

  /**
   * case 4:
   * removing head with list having 1 element
   * @assumptions:
   * 1: list size will be decremented by one ;tested
   * 2: list head will be null
   * 3: list tail will be null
   */

  to_remove = llist->head;
  Curl_llist_remove(llist, to_remove, NULL);
  fail_unless(llist->head == NULL,
              "llist head is not NULL while the llist is empty");
  fail_unless(llist->tail == NULL,
              "llist tail is not NULL while the llist is empty");

  /* @testing Curl_llist_move(struct curl_llist *,
   * struct curl_llist_element *, struct curl_llist *,
   * struct curl_llist_element *);
  */

  /**
   * @case 1:
   * moving head from an llist containg one element to an empty llist
   * @assumptions:
   * 1: llist size will be 0
   * 2: llist_destination size will be 1
   * 3: llist head will be NULL
   * 4: llist_destination head == llist_destination tail != NULL
   */

  /*
  * @setup
  * add one element to the list
  */

  curlErrCode = Curl_llist_insert_next(llist, llist->head, &unusedData_case1);
  /* necessary assertions */

  abort_unless(curlErrCode == 1,
  "Curl_llist_insert_next returned an error, Can't move on with test");
  abort_unless(Curl_llist_count(llist) == 1,
  "Number of list elements is not as expected, Aborting");
  abort_unless(Curl_llist_count(llist_destination) == 0,
  "Number of list elements is not as expected, Aborting");

  /*actual testing code*/
  curlErrCode = Curl_llist_move(llist, llist->head, llist_destination, NULL);
  abort_unless(curlErrCode == 1,
  "Curl_llist_move returned an error, Can't move on with test");
  fail_unless(Curl_llist_count(llist) == 0,
      "moving element from llist didn't decrement the size");

  fail_unless(Curl_llist_count(llist_destination) == 1,
        "moving element to llist_destination didn't increment the size");

  fail_unless(llist->head == NULL,
      "llist head not set to null after moving the head");

  fail_unless(llist_destination->head != NULL,
        "llist_destination head set to null after moving an element");

  fail_unless(llist_destination->tail != NULL,
          "llist_destination tail set to null after moving an element");

  fail_unless(llist_destination->tail == llist_destination->tail,
            "llist_destination tail doesn't equal llist_destination head");



UNITTEST_STOP
