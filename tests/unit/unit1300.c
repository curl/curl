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
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "unitcheck.h"

#include "llist.h"
#include "unitprotos.h"

static void test_Curl_llist_dtor(void *key, void *value)
{
  /* used by the llist API, does nothing here */
  (void)key;
  (void)value;
}

static CURLcode test_unit1300(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  struct Curl_llist llist;
  struct Curl_llist llist_destination;

  int unusedData_case1 = 1;
  int unusedData_case2 = 2;
  int unusedData_case3 = 3;
  struct Curl_llist_node case1_list;
  struct Curl_llist_node case2_list;
  struct Curl_llist_node case3_list;
  struct Curl_llist_node case4_list;
  struct Curl_llist_node *head;
  struct Curl_llist_node *element_next;
  struct Curl_llist_node *element_prev;
  struct Curl_llist_node *to_remove;
  size_t llist_size;

  Curl_llist_init(&llist, test_Curl_llist_dtor);
  Curl_llist_init(&llist_destination, test_Curl_llist_dtor);

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

  fail_unless(Curl_llist_count(&llist) == 0,
              "list initial size should be zero");
  fail_unless(Curl_llist_head(&llist) == NULL,
              "list head should initiate to NULL");
  fail_unless(Curl_llist_tail(&llist) == NULL,
              "list tail should initiate to NULL");

  /**
   * testing Curl_llist_insert_next
   * case 1:
   * list is empty
   * @assumptions:
   * 1: list size will be 1
   * 2: list head will hold the data "unusedData_case1"
   * 3: list tail will be the same as list head
   */

  Curl_llist_insert_next(&llist, Curl_llist_head(&llist), &unusedData_case1,
                         &case1_list);

  fail_unless(Curl_llist_count(&llist) == 1,
              "List size should be 1 after adding a new element");
  /* test that the list head data holds my unusedData */
  fail_unless(Curl_node_elem(Curl_llist_head(&llist)) == &unusedData_case1,
              "head ptr should be first entry");
  /* same goes for the list tail */
  fail_unless(Curl_llist_tail(&llist) == Curl_llist_head(&llist),
              "tail and head should be the same");

  /**
   * testing Curl_llist_insert_next
   * case 2:
   * list has 1 element, adding one element after the head
   * @assumptions:
   * 1: the element next to head should be our newly created element
   * 2: the list tail should be our newly created element
   */

  Curl_llist_insert_next(&llist, Curl_llist_head(&llist),
                         &unusedData_case3, &case3_list);
  fail_unless(Curl_node_elem(Curl_node_next(Curl_llist_head(&llist))) ==
              &unusedData_case3,
              "the node next to head is not getting set correctly");
  fail_unless(Curl_node_elem(Curl_llist_tail(&llist)) == &unusedData_case3,
              "the list tail is not getting set correctly");

  /**
   * testing Curl_llist_insert_next
   * case 3:
   * list has >1 element, adding one element after "NULL"
   * @assumptions:
   * 1: the element next to head should be our newly created element
   * 2: the list tail should different from newly created element
   */

  Curl_llist_insert_next(&llist, Curl_llist_head(&llist),
                         &unusedData_case2, &case2_list);
  fail_unless(Curl_node_elem(Curl_node_next(Curl_llist_head(&llist))) ==
              &unusedData_case2,
              "the node next to head is not getting set correctly");
  /* better safe than sorry, check that the tail isn't corrupted */
  fail_unless(Curl_node_elem(Curl_llist_tail(&llist)) != &unusedData_case2,
              "the list tail is not getting set correctly");

  /* unit tests for Curl_node_remove */

  /**
   * case 1:
   * list has >1 element, removing head
   * @assumptions:
   * 1: list size will be decremented by one
   * 2: head will be the head->next
   * 3: "new" head's previous will be NULL
   */

  head = Curl_llist_head(&llist);
  abort_unless(head, "llist.head is NULL");
  element_next = Curl_node_next(head);
  llist_size = Curl_llist_count(&llist);

  Curl_node_remove(Curl_llist_head(&llist));

  fail_unless(Curl_llist_count(&llist) ==  (llist_size-1),
              "llist size not decremented as expected");
  fail_unless(Curl_llist_head(&llist) == element_next,
              "llist new head not modified properly");
  abort_unless(Curl_llist_head(&llist), "llist.head is NULL");
  fail_unless(Curl_node_prev(Curl_llist_head(&llist)) == NULL,
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
  Curl_llist_insert_next(&llist, Curl_llist_head(&llist), &unusedData_case3,
                         &case4_list);
  llist_size = Curl_llist_count(&llist);
  fail_unless(llist_size == 3, "should be 3 list members");

  to_remove = Curl_node_next(Curl_llist_head(&llist));
  abort_unless(to_remove, "to_remove is NULL");
  element_next = Curl_node_next(to_remove);
  element_prev = Curl_node_prev(to_remove);
  Curl_node_uremove(to_remove, NULL);
  fail_unless(Curl_node_next(element_prev) == element_next,
              "element previous->next is not being adjusted");
  abort_unless(element_next, "element_next is NULL");
  fail_unless(Curl_node_prev(element_next) == element_prev,
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

  to_remove = Curl_llist_tail(&llist);
  element_prev = Curl_node_prev(to_remove);
  Curl_node_remove(to_remove);
  fail_unless(Curl_llist_tail(&llist) == element_prev,
              "llist tail is not being adjusted when removing tail");

  /**
   * case 4:
   * removing head with list having 1 element
   * @assumptions:
   * 1: list size will be decremented by one ;tested
   * 2: list head will be null
   * 3: list tail will be null
   */

  to_remove = Curl_llist_head(&llist);
  Curl_node_remove(to_remove);
  fail_unless(Curl_llist_head(&llist) == NULL,
              "llist head is not NULL while the llist is empty");
  fail_unless(Curl_llist_tail(&llist) == NULL,
              "llist tail is not NULL while the llist is empty");

  /**
   * testing Curl_llist_append
   * case 1:
   * list is empty
   * @assumptions:
   * 1: the element next to head should be our newly created element
   * 2: the list tail should different from newly created element
   */
  Curl_llist_append(&llist, &unusedData_case1, &case1_list);
  fail_unless(Curl_llist_count(&llist) == 1,
              "List size should be 1 after appending a new element");
  /* test that the list head data holds my unusedData */
  fail_unless(Curl_node_elem(Curl_llist_head(&llist)) == &unusedData_case1,
              "head ptr should be first entry");
  /* same goes for the list tail */
  fail_unless(Curl_llist_tail(&llist) == Curl_llist_head(&llist),
              "tail and head should be the same");

  /**
   * testing Curl_llist_append
   * case 2:
   * list is not empty
   * @assumptions:
   * 1: the list head-next should be the newly created element
   * 2: the list tail should be the newly created element
   */
  Curl_llist_append(&llist, &unusedData_case2, &case2_list);
  fail_unless(Curl_node_elem(Curl_node_next(Curl_llist_head(&llist))) ==
              &unusedData_case2,
              "the node next to head is not getting set correctly");
  fail_unless(Curl_node_elem(Curl_llist_tail(&llist)) == &unusedData_case2,
              "the list tail is not getting set correctly");

  /**
   * testing Curl_llist_append
   * case 3:
   * list is has 2 members
   * @assumptions:
   * 1: the list head-next should remain the same
   * 2: the list tail should be the newly created element
   */
  Curl_llist_append(&llist, &unusedData_case3, &case3_list);
  fail_unless(Curl_node_elem(Curl_node_next(Curl_llist_head(&llist))) ==
              &unusedData_case2,
              "the node next to head did not stay the same");
  fail_unless(Curl_node_elem(Curl_llist_tail(&llist)) == &unusedData_case3,
              "the list tail is not getting set correctly");

  Curl_llist_destroy(&llist, NULL);
  Curl_llist_destroy(&llist_destination, NULL);

  UNITTEST_END_SIMPLE
}
