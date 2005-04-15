/* $Id$ */

/*
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#ifndef ARES_IPV6_H
#define ARES_IPV6_H

#ifndef HAVE_PF_INET6
#define PF_INET6 AF_INET6
#endif

#ifndef HAVE_STRUCT_IN6_ADDR
struct in6_addr
{
  unsigned char s6_addr[16];
};
#endif

#ifndef NS_IN6ADDRSZ
#define NS_IN6ADDRSZ SIZEOF_STRUCT_IN6_ADDR
#endif

#ifndef NS_INADDRSZ
#define NS_INADDRSZ SIZEOF_STRUCT_IN_ADDR
#endif

#ifndef NS_INT16SZ
#define NS_INT16SZ 2
#endif

#endif /* ARES_IPV6_H */
