/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef NETWARE /* Novell NetWare */

#include <stdlib.h>

#ifdef __NOVELL_LIBC__
/* For native LibC-based NLM we need to do nothing. */
int netware_init ( void )
{
    return 0;
}

#else /* __NOVELL_LIBC__ */

/* For native CLib-based NLM we need to initialize the LONG namespace. */
#include <stdio.h>
#include <nwnspace.h>
#include <nwfileio.h>
#include <nwthread.h>
#include <nwadv.h>
/* Make the CLIB Ctx stuff link */
#include <netdb.h>
NETDB_DEFINE_CONTEXT

int netware_init ( void )
{
    int rc = 0;
    /* import UnAugmentAsterisk dynamically for NW4.x compatibility */
    unsigned int myHandle = GetNLMHandle();
    void (*pUnAugmentAsterisk)(int) = (void(*)(int))
            ImportSymbol(myHandle, "UnAugmentAsterisk");
    if (pUnAugmentAsterisk)
        pUnAugmentAsterisk(1);
    UnimportSymbol(myHandle, "UnAugmentAsterisk");
    /* set long name space */
    if ((SetCurrentNameSpace(4) == 255)) {
        rc = 1;
    }
    if ((SetTargetNameSpace(4) == 255)) {
        rc = rc + 2;
    }
    UseAccurateCaseForPaths(1);
    return rc;
}

/* dummy function to satisfy newer prelude */
int __init_environment ( void )
{
    return 0;
}

/* dummy function to satisfy newer prelude */
int __deinit_environment ( void )
{
    return 0;
}

#endif /* __NOVELL_LIBC__ */

#endif /* NETWARE */


