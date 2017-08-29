/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017, Max Dymond, <cmeister2@gmail.com>, et al.
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * Fuzzing entry point. This function is passed a buffer containing a test
 * case.  This test case should drive the CURL API into making a request.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  /* Use a dummy function for now. */
  printf("Data: %p  size: %zu \n", data, size);
  return 0;
}
