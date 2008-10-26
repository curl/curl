/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 */



#include "test.h"

#include "memdebug.h"

#define TABLE_SIZE 10


struct element_st {
  int idx;
  int dummy;
};


struct root_st {
  struct element_st **table;
  int size;
};


static
struct root_st * new_root(void)
{
  struct root_st *r;

  r = malloc(sizeof(struct root_st));
  if(r != NULL)
    printf("malloc of root struct OK\n");
  else {
    printf("malloc of root struct failed\n");
    return NULL;
  }

  r->size = TABLE_SIZE;
  r->table = malloc(r->size * sizeof(struct element_st *));
  if(r->table != NULL)
    printf("malloc of pointer table OK\n");
  else {
    printf("malloc of pointer table failed\n");
    free(r);
    return NULL;
  }

  return r;
}


static
struct element_st * new_element(int idx)
{
  struct element_st *e;

  e = malloc(sizeof(struct element_st));
  if(e != NULL)
    printf("malloc of pointed element (idx %d) OK\n", idx);
  else {
    printf("malloc of pointed element (idx %d) failed\n", idx);
    return NULL;
  }

  e->idx = e->dummy = idx;

  return e;
}


int test(char *URL)
{
  struct root_st *root;
  int error;
  int i;
  (void)URL; /* not used */

  root = new_root();
  if(!root)
    return TEST_ERR_MAJOR_BAD;

  printf("initializing table...\n");
  for (i = 0; i < root->size; ++i) {
    root->table[i] = NULL;
  }
  printf("table initialized OK\n");

  printf("filling pointer table...\n");
  error = 0;
  for (i = 0; i < root->size; ++i) {
    root->table[i] = new_element(i);
    if(!root->table[i]) {
      error = 1;
      break;
    }
  }
  if(error) {
    printf("pointer table filling failed\n");
    return TEST_ERR_MAJOR_BAD;
  }
  else
    printf("pointer table filling OK\n");

  printf("freeing pointers in table...\n");
  for (i = 0; i < root->size; ++i) {
    if(root->table[i])
      free(root->table[i]);
  }
  printf("freeing pointers in table OK\n");

  printf("freeing table...\n");
  free(root->table);
  printf("freeing table OK\n");

  printf("freeing root struct...\n");
  free(root);
  printf("freeing root struct OK\n");

  return 0; /* OK */
}
