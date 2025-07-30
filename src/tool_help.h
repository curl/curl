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

#include "tool_help_cheatsheet.h"
#include "tool_help.h"
#include "terminal.h"

#include "memdebug.h" /* keep this as LAST include */

int incre_i(int i, int j) {
  if (j == 0)
    return i + 1;
  else
    return i + 1 + j;
}
 
/* Support to print number of columns per screen width. */
static void print_one(int i) {
  if(cheat_items[i].heading[0] != NULL &&
     cheat_items[i].heading[0] != "")
    printf("%-20s\n%s\n%s\n\n",
     cheat_items[i].heading[0], spacer, cheat_items[i].heading[1]);
}
static void print_two(int i) {
  if(cheat_items[i+1].heading[0] == NULL ||
     cheat_items[i+1].heading[0] == "")
    print_one(i);
  else
    if (cheat_items[i].heading[0] != NULL &&
        cheat_items[i].heading[0] != "")
      printf("%-*s %-*s\n%s %s\n%-*s %-*s\n\n",
        width, cheat_items[i].heading[0],
        width, cheat_items[i+1].heading[0],
        spacer, spacer,
        width, cheat_items[i].heading[1],
        width, cheat_items[i+1].heading[1]);
}
static void print_three(int i) {
  if(cheat_items[i+1].heading[0] == NULL ||
     cheat_items[i+1].heading[0] == "")
    print_one(i);
  else if (cheat_items[i+2].heading[0] == NULL ||
           cheat_items[i+2].heading[0] == "")
    print_two(i);
  else
    if (cheat_items[i].heading[0] != NULL &&
        cheat_items[i].heading[0] != "")
      printf("%-*s %-*s %-*s\n%s %s %s\n%-*s %-*s %-*s\n\n",
        width, cheat_items[i].heading[0],
        width, cheat_items[i+1].heading[0],
        width, cheat_items[i+2].heading[0],
        spacer, spacer, spacer,
        width, cheat_items[i].heading[1],
        width, cheat_items[i+1].heading[1],
        width, cheat_items[i+2].heading[1]);
}
static void print_four(int i) {
  if(cheat_items[i+1].heading[0] == NULL ||
     cheat_items[i+1].heading[0] == "")
    print_one(i);
  else if (cheat_items[i+2].heading[0] == NULL ||
           cheat_items[i+2].heading[0] == "")
    print_two(i);
  else if (cheat_items[i+3].heading[0] == NULL ||
           cheat_items[i+3].heading[0] == "")
    print_three(i);
  else
    if (cheat_items[i].heading[0] != NULL &&
        cheat_items[i].heading[0] != "")
      printf("%-*s %-*s %-*s %-*s\n%s %s %s %s\n"
             "%-*s %-*s %-*s %-*s\n\n",
        width, cheat_items[i].heading[0],
        width, cheat_items[i+1].heading[0],
        width, cheat_items[i+2].heading[0],
        width, cheat_items[i+3].heading[0],
        spacer, spacer, spacer, spacer,
        width, cheat_items[i].heading[1],
        width, cheat_items[i+1].heading[1],
        width, cheat_items[i+2].heading[1],
        width, cheat_items[i+3].heading[1]);
}
static void print_five(int i) {
  if(cheat_items[i+1].heading[0] == NULL ||
     cheat_items[i+1].heading[0] == "")
    print_one(i);
  else if (cheat_items[i+2].heading[0] == NULL ||
           cheat_items[i+2].heading[0] == "")
    print_two(i);
  else if (cheat_items[i+3].heading[0] == NULL ||
           cheat_items[i+3].heading[0] == "")
    print_three(i);
  else if (cheat_items[i+4].heading[0] == NULL ||
           cheat_items[i+4].heading[0] == "")
    print_four(i);
  else
    if (cheat_items[i].heading[0] != NULL &&
        cheat_items[i].heading[0] != "")
      printf("%-*s %-*s %-*s %-*s %-*s\n%s %s %s %s %s\n"
             "%-*s %-*s %-*s %-*s %-*s\n\n",
        width, cheat_items[i].heading[0],
        width, cheat_items[i+1].heading[0],
        width, cheat_items[i+2].heading[0],
        width, cheat_items[i+3].heading[0],
        width, cheat_items[i+4].heading[0],
        spacer, spacer, spacer, spacer, spacer,
        width, cheat_items[i].heading[1],
        width, cheat_items[i+1].heading[1],
        width, cheat_items[i+2].heading[1],
        width, cheat_items[i+3].heading[1],
        width, cheat_items[i+4].heading[1]);
}

/* Output cheat-sheet. */
CURL_EXTERN void tool_cheat_sheet(void)
{
  /* Get terminal width for proper formatting */
  unsigned int cols = get_terminal_columns();

  /* Cheat sheet data structure organized by heading and value. */
  static const struct cheat_table {
    const char *heading[2];
  } cheat_items[] = {
    /* Verbose section */
    {"Verbose", "-v, --trace-ascii file"},
    {"Hide progress", "-s"},
    {"extra info", "-w format"},
    {"Write output", "-O, -o file"},
    {"Timeout", "-m secs"},
    {"POST", "-d string, -d @file"},
    {"multipart", "-F name=value, -F name=@file"},
    {"PUT", "-T file"},
    {"HEAD", "-I"},
    {"custom", "-X METHOD"},
    {"Basic auth", "-u user:password"},
    {"read cookies", "-b <file>"},
    {"write cookies", "-c <file>"},
    {"send cookies", "-b \"c=1; d=2\""},
    {"user-agent", "-A string"},
    {"Use proxy", "-x host:port"},
    {"Headers add/remove", "-H \"name: value\", -H name:"},
    {"follow redirs", "-L"},
    {"gzip", "--compressed"},
    {"insecure", "-k"},
    {"", ""},
    {NULL, NULL}
  };
  
  /* Spacer variable for heading. */
  const char *spacer = "------------------------------";

  /* Use consistent width for each column. */
  int width = 30;

  /* Get the table length. */
  int table_length = sizeof(cheat_items) / sizeof(cheat_items[0]);

  /* Handle for loop according to cols */
  unsigned int i, j;

  /* Set j based on col width, setting once, not in a loop. */
  if (cols <= 75)
    j = 0;
  else if (cols > 75 && cols <= 125)
    j = 1;
  else if (cols > 125 &&  cols <= 175)
    j = 2;
  else if (cols > 175 && cols <= 225)
    j = 3;
  else
    j = 4;

  /* Loop through cheat sheet sections */
  for(i = 0; i < table_length; i = incre_i(i, j)) {
    if (cheat_items[i+j].heading[0] == NULL) {
      break;
    } else {
     if (cols <= 75)                    /* Output one columns.  */
       print_one(i);
     else if(cols > 75 && cols <= 125)  /* output two columns   */
       print_two(i);
     else if(cols > 125 && cols <= 175) /* output three columns */
       print_three(i);
     else if(cols > 175 && cols <= 225) /* output four columns  */
       print_four(i);
     else
       print_five(i);                   /* output five columns  */
    }
  }
}
