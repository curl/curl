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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ares.h"
#include "ares_private.h"

#ifdef WATT32
#undef WIN32
#endif

struct addr_query {
  /* Arguments passed to ares_gethostbyaddr() */
  ares_channel channel;
  struct in_addr addr;
  ares_host_callback callback;
  void *arg;

  const char *remaining_lookups;
};

static void next_lookup(struct addr_query *aquery);
static void addr_callback(void *arg, int status, unsigned char *abuf,
                          int alen);
static void end_aquery(struct addr_query *aquery, int status,
                       struct hostent *host);
static int file_lookup(struct in_addr *addr, struct hostent **host);

void ares_gethostbyaddr(ares_channel channel, const void *addr, int addrlen,
                        int family, ares_host_callback callback, void *arg)
{
  struct addr_query *aquery;

  if (family != AF_INET || addrlen != sizeof(struct in_addr))
    {
      callback(arg, ARES_ENOTIMP, NULL);
      return;
    }

  aquery = malloc(sizeof(struct addr_query));
  if (!aquery)
    {
      callback(arg, ARES_ENOMEM, NULL);
      return;
    }
  aquery->channel = channel;
  memcpy(&aquery->addr, addr, sizeof(aquery->addr));
  aquery->callback = callback;
  aquery->arg = arg;
  aquery->remaining_lookups = channel->lookups;

  next_lookup(aquery);
}

static void next_lookup(struct addr_query *aquery)
{
  const char *p;
  char name[64];
  int a1, a2, a3, a4, status;
  struct hostent *host;
  unsigned long addr;

  for (p = aquery->remaining_lookups; *p; p++)
    {
      switch (*p)
        {
        case 'b':
          addr = ntohl(aquery->addr.s_addr);
          a1 = (int)((addr >> 24) & 0xff);
          a2 = (int)((addr >> 16) & 0xff);
          a3 = (int)((addr >> 8) & 0xff);
          a4 = (int)(addr & 0xff);
          sprintf(name, "%d.%d.%d.%d.in-addr.arpa", a4, a3, a2, a1);
          aquery->remaining_lookups = p + 1;
          ares_query(aquery->channel, name, C_IN, T_PTR, addr_callback,
                     aquery);
          return;
        case 'f':
          status = file_lookup(&aquery->addr, &host);
          if (status != ARES_ENOTFOUND)
            {
              end_aquery(aquery, status, host);
              return;
            }
          break;
        }
    }
  end_aquery(aquery, ARES_ENOTFOUND, NULL);
}

static void addr_callback(void *arg, int status, unsigned char *abuf, int alen)
{
  struct addr_query *aquery = (struct addr_query *) arg;
  struct hostent *host;

  if (status == ARES_SUCCESS)
    {
      status = ares_parse_ptr_reply(abuf, alen, &aquery->addr,
                                    sizeof(struct in_addr), AF_INET, &host);
      end_aquery(aquery, status, host);
    }
  else if (status == ARES_EDESTRUCTION)
    end_aquery(aquery, status, NULL);
  else
    next_lookup(aquery);
}

static void end_aquery(struct addr_query *aquery, int status,
                       struct hostent *host)
{
  aquery->callback(aquery->arg, status, host);
  if (host)
    ares_free_hostent(host);
  free(aquery);
}

static int file_lookup(struct in_addr *addr, struct hostent **host)
{
  FILE *fp;
  int status;

#ifdef WIN32
  char PATH_HOSTS[MAX_PATH];
  if (IS_NT()) {
    char tmp[MAX_PATH];
    HKEY hkeyHosts;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, WIN_NS_NT_KEY, 0, KEY_READ, &hkeyHosts)
        == ERROR_SUCCESS)
    {
      DWORD dwLength = MAX_PATH;
      RegQueryValueEx(hkeyHosts, DATABASEPATH, NULL, NULL, (LPBYTE)tmp,
                      &dwLength);
      ExpandEnvironmentStrings(tmp, PATH_HOSTS, MAX_PATH);
      RegCloseKey(hkeyHosts);
    }
  }
  else
    GetWindowsDirectory(PATH_HOSTS, MAX_PATH);

  strcat(PATH_HOSTS, WIN_PATH_HOSTS);

#elif defined(WATT32)
  extern const char *_w32_GetHostsFile (void);
  const char *PATH_HOSTS = _w32_GetHostsFile();

  if (!PATH_HOSTS)
    return ARES_ENOTFOUND;
#endif

  fp = fopen(PATH_HOSTS, "r");
  if (!fp)
    return ARES_ENOTFOUND;

  while ((status = ares__get_hostent(fp, host)) == ARES_SUCCESS)
    {
      if (memcmp((*host)->h_addr, addr, sizeof(struct in_addr)) == 0)
        break;
      ares_free_hostent(*host);
    }
  fclose(fp);
  if (status == ARES_EOF)
    status = ARES_ENOTFOUND;
  if (status != ARES_SUCCESS)
    *host = NULL;
  return status;
}
