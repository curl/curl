/* Copyright (C) 2009 Jakub Hrozek <jhrozek@redhat.com>
*
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

#include "setup.h"

#if defined(WIN32) && !defined(WATT32)
#include "nameser.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#endif

#include <stdlib.h>
#include <string.h>
#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"

int
ares_parse_txt_reply (const unsigned char *abuf, int alen,
                      struct ares_txt_reply **txt_out, int *ntxtreply)
{
  unsigned char substr_len = 0;
  unsigned char str_len = 0;
  unsigned int qdcount, ancount;
  const unsigned char *aptr;
  const unsigned char *strptr;
  int status, i, rr_type, rr_class, rr_len;
  long len;
  char *hostname = NULL, *rr_name = NULL;
  struct ares_txt_reply *txt = NULL;

  *txt_out = NULL;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return ARES_EBADRESP;

  /* Fetch the question and answer count from the header. */
  qdcount = DNS_HEADER_QDCOUNT (abuf);
  ancount = DNS_HEADER_ANCOUNT (abuf);
  if (qdcount != 1)
    return ARES_EBADRESP;
  if (ancount == 0)
    return ARES_ENODATA;

  /* Expand the name from the question, and skip past the question. */
  aptr = abuf + HFIXEDSZ;
  status = ares_expand_name (aptr, abuf, alen, &hostname, &len);
  if (status != ARES_SUCCESS)
    return status;

  if (aptr + len + QFIXEDSZ > abuf + alen)
    {
      free (hostname);
      return ARES_EBADRESP;
    }
  aptr += len + QFIXEDSZ;

  /* Allocate ares_txt_reply array; ancount gives an upper bound */
  txt = malloc ((ancount) * sizeof (struct ares_txt_reply));
  if (!txt)
    {
      free (hostname);
      return ARES_ENOMEM;
    }
  /* Zero out so we can safely free txt.txt even if NULL */
  memset(txt, 0, ancount * sizeof (struct ares_txt_reply));

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < (int) ancount; i++)
    {
      /* Decode the RR up to the data field. */
      status = ares_expand_name (aptr, abuf, alen, &rr_name, &len);
      if (status != ARES_SUCCESS)
        {
          break;
        }
      aptr += len;
      if (aptr + RRFIXEDSZ > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }
      rr_type = DNS_RR_TYPE (aptr);
      rr_class = DNS_RR_CLASS (aptr);
      rr_len = DNS_RR_LEN (aptr);
      aptr += RRFIXEDSZ;

      /* Check if we are really looking at a TXT record */
      if (rr_class == C_IN && rr_type == T_TXT)
        {
          /*
           * There may be multiple substrings in a single TXT record. Each
           * substring may be up to 255 characters in length, with a
           * "length byte" indicating the size of the substring payload.
           * RDATA contains both the length-bytes and payloads of all
           * substrings contained therein.
           */

          /* Realloc would be expensive, compute the total length */
          txt[i].length = 0;
          strptr = aptr;
          while (strptr < (aptr + rr_len))
            {
              memcpy ((void *) &substr_len, strptr, sizeof (unsigned char));
              txt[i].length += substr_len;
              strptr += substr_len + 1;
            }

          /* Including null byte */
          txt[i].txt = malloc (sizeof (unsigned char) * (txt[i].length + 1));
          if (txt[i].txt == NULL)
            {
              status = ARES_ENOMEM;
              break;
            }

          /* Step through the list of substrings, concatenating them */
          substr_len = 0;
          str_len = 0;
          strptr = aptr;
          while (strptr < (aptr + rr_len))
            {
              memcpy ((void *) &substr_len, strptr, sizeof (unsigned char));
              strptr++;
              memcpy ((void *) txt[i].txt + str_len, strptr,
                      sizeof (unsigned char) * substr_len);
              str_len += substr_len;
              strptr += substr_len;
            }
          /* Make sure we NULL-terminate */
          txt[i].txt[txt[i].length] = '\0';

          /* Move on to the next record */
          aptr += rr_len;
        }

      /* Don't lose memory in the next iteration */
      free (rr_name);
      rr_name = NULL;
    }

  free (hostname);
  free (rr_name);

  /* clean up on error */
  if (status != ARES_SUCCESS)
    {
      ares_free_txt_reply(txt, ancount);
      return status;
    }

  /* everything looks fine, return the data */
  *txt_out = txt;
  *ntxtreply = ancount;
  return 0;
}
