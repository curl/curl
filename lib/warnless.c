/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

#include "setup.h"

#include "warnless.h"

unsigned short curlx_ultous(unsigned long ulnum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  return (unsigned short)(ulnum & 0xFFFFUL);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

unsigned char curlx_ultouc(unsigned long ulnum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  return (unsigned char)(ulnum & 0xFFUL);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}
