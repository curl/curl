/* Copyright 1998 by the Massachusetts Institute of Technology.
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
#include <sys/types.h>

#if defined(WIN32) && !defined(WATT32)
#include "nameser.h"
#else
#include <netinet/in.h>
#include <arpa/nameser.h>
#endif

#include <stdlib.h>
#include <string.h>
#include "ares.h"
#include "ares_dns.h"

/* Header format, from RFC 1035:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      ID                       |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    QDCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ANCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    NSCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ARCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * AA, TC, RA, and RCODE are only set in responses.  Brief description
 * of the remaining fields:
 *	ID	Identifier to match responses with queries
 *	QR	Query (0) or response (1)
 *	Opcode	For our purposes, always QUERY
 * 	RD	Recursion desired
 *	Z	Reserved (zero)
 *	QDCOUNT	Number of queries
 *	ANCOUNT	Number of answers
 *	NSCOUNT	Number of name server records
 *	ARCOUNT	Number of additional records
 *
 * Question format, from RFC 1035:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                                               |
 *  /                     QNAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QTYPE                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QCLASS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * The query name is encoded as a series of labels, each represented
 * as a one-byte length (maximum 63) followed by the text of the
 * label.  The list is terminated by a label of length zero (which can
 * be thought of as the root domain).
 */

int ares_mkquery(const char *name, int dnsclass, int type, unsigned short id,
		 int rd, unsigned char **buf, int *buflen)
{
  int len;
  unsigned char *q;
  const char *p;

  /* Compute the length of the encoded name so we can check buflen.
   * Start counting at 1 for the zero-length label at the end. */
  len = 1;
  for (p = name; *p; p++)
    {
      if (*p == '\\' && *(p + 1) != 0)
	p++;
      len++;
    }
  /* If there are n periods in the name, there are n + 1 labels, and
   * thus n + 1 length fields, unless the name is empty or ends with a
   * period.  So add 1 unless name is empty or ends with a period.
   */
  if (*name && *(p - 1) != '.')
    len++;

  *buflen = len + HFIXEDSZ + QFIXEDSZ;
  *buf = malloc(*buflen);
  if (!*buf)
      return ARES_ENOMEM;

  /* Set up the header. */
  q = *buf;
  memset(q, 0, HFIXEDSZ);
  DNS_HEADER_SET_QID(q, id);
  DNS_HEADER_SET_OPCODE(q, QUERY);
  DNS_HEADER_SET_RD(q, (rd) ? 1 : 0);
  DNS_HEADER_SET_QDCOUNT(q, 1);

  /* A name of "." is a screw case for the loop below, so adjust it. */
  if (strcmp(name, ".") == 0)
    name++;

  /* Start writing out the name after the header. */
  q += HFIXEDSZ;
  while (*name)
    {
      if (*name == '.')
	return ARES_EBADNAME;

      /* Count the number of bytes in this label. */
      len = 0;
      for (p = name; *p && *p != '.'; p++)
	{
	  if (*p == '\\' && *(p + 1) != 0)
	    p++;
	  len++;
	}
      if (len > MAXLABEL)
	return ARES_EBADNAME;

      /* Encode the length and copy the data. */
      *q++ = len;
      for (p = name; *p && *p != '.'; p++)
	{
	  if (*p == '\\' && *(p + 1) != 0)
	    p++;
	  *q++ = *p;
	}

      /* Go to the next label and repeat, unless we hit the end. */
      if (!*p)
	break;
      name = p + 1;
    }

  /* Add the zero-length label at the end. */
  *q++ = 0;

  /* Finish off the question with the type and class. */
  DNS_QUESTION_SET_TYPE(q, type);
  DNS_QUESTION_SET_CLASS(q, dnsclass);

  return ARES_SUCCESS;
}
