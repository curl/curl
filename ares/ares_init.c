/* $Id$ */

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
#include <iphlpapi.h>
#include <malloc.h>

#else
#include <sys/param.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include "ares.h"
#include "ares_private.h"
#include "inet_net_pton.h"

#ifdef WATT32
#undef WIN32  /* Redefined in MingW/MSVC headers */
#endif

static int init_by_options(ares_channel channel, struct ares_options *options,
                           int optmask);
static int init_by_environment(ares_channel channel);
static int init_by_resolv_conf(ares_channel channel);
static int init_by_defaults(ares_channel channel);

static int config_nameserver(struct server_state **servers, int *nservers,
                             char *str);
static int set_search(ares_channel channel, const char *str);
static int set_options(ares_channel channel, const char *str);
static const char *try_option(const char *p, const char *q, const char *opt);
#ifndef WIN32
static int sortlist_alloc(struct apattern **sortlist, int *nsort, struct apattern *pat);
static int ip_addr(const char *s, int len, struct in_addr *addr);
static void natural_mask(struct apattern *pat);
static int config_domain(ares_channel channel, char *str);
static int config_lookup(ares_channel channel, const char *str,
                         const char *bindch, const char *filech);
static int config_sortlist(struct apattern **sortlist, int *nsort,
                           const char *str);
static char *try_config(char *s, const char *opt);
#endif

int ares_init(ares_channel *channelptr)
{
  return ares_init_options(channelptr, NULL, 0);
}

int ares_init_options(ares_channel *channelptr, struct ares_options *options,
                      int optmask)
{
  ares_channel channel;
  int i, status;
  struct server_state *server;
  struct timeval tv;

#ifdef CURLDEBUG
  const char *env = getenv("CARES_MEMDEBUG");

  if (env)
    curl_memdebug(env);
  env = getenv("CARES_MEMLIMIT");
  if (env)
    curl_memlimit(atoi(env));
#endif

  channel = malloc(sizeof(struct ares_channeldata));
  if (!channel)
    return ARES_ENOMEM;

  /* Set everything to distinguished values so we know they haven't
   * been set yet.
   */
  channel->flags = -1;
  channel->timeout = -1;
  channel->tries = -1;
  channel->ndots = -1;
  channel->udp_port = -1;
  channel->tcp_port = -1;
  channel->nservers = -1;
  channel->ndomains = -1;
  channel->nsort = -1;
  channel->lookups = NULL;
  channel->queries = NULL;
  channel->domains = NULL;
  channel->sortlist = NULL;
  channel->sock_state_cb = NULL;

  /* Initialize configuration by each of the four sources, from highest
   * precedence to lowest.
   */
  status = init_by_options(channel, options, optmask);
  if (status == ARES_SUCCESS)
    status = init_by_environment(channel);
  if (status == ARES_SUCCESS)
    status = init_by_resolv_conf(channel);
  if (status == ARES_SUCCESS)
    status = init_by_defaults(channel);
  if (status != ARES_SUCCESS)
    {
      /* Something failed; clean up memory we may have allocated. */
      if (channel->nservers != -1)
        free(channel->servers);
      if (channel->domains)
        {
          for (i = 0; i < channel->ndomains; i++)
            free(channel->domains[i]);
          free(channel->domains);
        }
      if (channel->sortlist)
        free(channel->sortlist);
      if(channel->lookups)
        free(channel->lookups);
      free(channel);
      return status;
    }

  /* Trim to one server if ARES_FLAG_PRIMARY is set. */
  if ((channel->flags & ARES_FLAG_PRIMARY) && channel->nservers > 1)
    channel->nservers = 1;

  /* Initialize server states. */
  for (i = 0; i < channel->nservers; i++)
    {
      server = &channel->servers[i];
      server->udp_socket = ARES_SOCKET_BAD;
      server->tcp_socket = ARES_SOCKET_BAD;
      server->tcp_lenbuf_pos = 0;
      server->tcp_buffer = NULL;
      server->qhead = NULL;
      server->qtail = NULL;
    }

  /* Choose a somewhat random query ID.  The main point is to avoid
   * collisions with stale queries.  An attacker trying to spoof a DNS
   * answer also has to guess the query ID, but it's only a 16-bit
   * field, so there's not much to be done about that.
   */
  gettimeofday(&tv, NULL);
  channel->next_id = (unsigned short)
    (tv.tv_sec ^ tv.tv_usec ^ getpid()) & 0xffff;

  channel->queries = NULL;

  *channelptr = channel;
  return ARES_SUCCESS;
}

static int init_by_options(ares_channel channel, struct ares_options *options,
                           int optmask)
{
  int i;

  /* Easy stuff. */
  if ((optmask & ARES_OPT_FLAGS) && channel->flags == -1)
    channel->flags = options->flags;
  if ((optmask & ARES_OPT_TIMEOUT) && channel->timeout == -1)
    channel->timeout = options->timeout;
  if ((optmask & ARES_OPT_TRIES) && channel->tries == -1)
    channel->tries = options->tries;
  if ((optmask & ARES_OPT_NDOTS) && channel->ndots == -1)
    channel->ndots = options->ndots;
  if ((optmask & ARES_OPT_UDP_PORT) && channel->udp_port == -1)
    channel->udp_port = options->udp_port;
  if ((optmask & ARES_OPT_TCP_PORT) && channel->tcp_port == -1)
    channel->tcp_port = options->tcp_port;
  if ((optmask & ARES_OPT_SOCK_STATE_CB) && channel->sock_state_cb == NULL)
    {
      channel->sock_state_cb = options->sock_state_cb;
      channel->sock_state_cb_data = options->sock_state_cb_data;
    }

  /* Copy the servers, if given. */
  if ((optmask & ARES_OPT_SERVERS) && channel->nservers == -1)
    {
      channel->servers =
        malloc(options->nservers * sizeof(struct server_state));
      if (!channel->servers && options->nservers != 0)
        return ARES_ENOMEM;
      for (i = 0; i < options->nservers; i++)
        channel->servers[i].addr = options->servers[i];
      channel->nservers = options->nservers;
    }

  /* Copy the domains, if given.  Keep channel->ndomains consistent so
   * we can clean up in case of error.
   */
  if ((optmask & ARES_OPT_DOMAINS) && channel->ndomains == -1)
    {
      channel->domains = malloc(options->ndomains * sizeof(char *));
      if (!channel->domains && options->ndomains != 0)
        return ARES_ENOMEM;
      for (i = 0; i < options->ndomains; i++)
        {
          channel->ndomains = i;
          channel->domains[i] = strdup(options->domains[i]);
          if (!channel->domains[i])
            return ARES_ENOMEM;
        }
      channel->ndomains = options->ndomains;
    }

  /* Set lookups, if given. */
  if ((optmask & ARES_OPT_LOOKUPS) && !channel->lookups)
    {
      channel->lookups = strdup(options->lookups);
      if (!channel->lookups)
        return ARES_ENOMEM;
    }

  return ARES_SUCCESS;
}

static int init_by_environment(ares_channel channel)
{
  const char *localdomain, *res_options;
  int status;

  localdomain = getenv("LOCALDOMAIN");
  if (localdomain && channel->ndomains == -1)
    {
      status = set_search(channel, localdomain);
      if (status != ARES_SUCCESS)
        return status;
    }

  res_options = getenv("RES_OPTIONS");
  if (res_options)
    {
      status = set_options(channel, res_options);
      if (status != ARES_SUCCESS)
        return status;
    }

  return ARES_SUCCESS;
}

#ifdef WIN32
/*
 * Warning: returns a dynamically allocated buffer, the user MUST
 * use free() if the function returns 1
 */
static int get_res_nt(HKEY hKey, const char *subkey, char **obuf)
{
  /* Test for the size we need */
  DWORD size = 0;
  int result;

  result = RegQueryValueEx(hKey, subkey, 0, NULL, NULL, &size);
  if ((result != ERROR_SUCCESS && result != ERROR_MORE_DATA) || !size)
    return 0;
  *obuf = malloc(size+1);
  if (!*obuf)
    return 0;

  if (RegQueryValueEx(hKey, subkey, 0, NULL,
                      (LPBYTE)*obuf, &size) != ERROR_SUCCESS)
  {
    free(*obuf);
    return 0;
  }
  if (size == 1)
  {
    free(*obuf);
    return 0;
  }
  return 1;
}

static int get_res_interfaces_nt(HKEY hKey, const char *subkey, char **obuf)
{
  char enumbuf[39]; /* GUIDs are 38 chars + 1 for NULL */
  DWORD enum_size = 39;
  int idx = 0;
  HKEY hVal;

  while (RegEnumKeyEx(hKey, idx++, enumbuf, &enum_size, 0,
                      NULL, NULL, NULL) != ERROR_NO_MORE_ITEMS)
  {
    int rc;

    enum_size = 39;
    if (RegOpenKeyEx(hKey, enumbuf, 0, KEY_QUERY_VALUE, &hVal) !=
        ERROR_SUCCESS)
      continue;
    rc = get_res_nt(hVal, subkey, obuf);
      RegCloseKey(hVal);
    if (rc)
      return 1;
    }
  return 0;
}

static int get_iphlpapi_dns_info (char *ret_buf, size_t ret_size)
{
  FIXED_INFO    *fi   = alloca (sizeof(*fi));
  DWORD          size = sizeof (*fi);
  typedef DWORD (WINAPI* get_net_param_func) (FIXED_INFO*, DWORD*);
  get_net_param_func GetNetworkParams;  /* available only on Win-98/2000+ */
  HMODULE        handle;
  IP_ADDR_STRING *ipAddr;
  int            i, count = 0;
  int            debug  = 0;
  size_t         ip_size = sizeof("255.255.255.255,")-1;
  size_t         left = ret_size;
  char          *ret = ret_buf;
  HRESULT        res;

  if (!fi)
     return (0);

  handle = LoadLibrary ("iphlpapi.dll");
  if (!handle)
     return (0);

  GetNetworkParams = (get_net_param_func) GetProcAddress (handle, "GetNetworkParams");
  if (!GetNetworkParams)
     goto quit;

  res = (*GetNetworkParams) (fi, &size);
  if ((res != ERROR_BUFFER_OVERFLOW) && (res != ERROR_SUCCESS))
     goto quit;

  fi = alloca (size);
  if (!fi || (*GetNetworkParams) (fi, &size) != ERROR_SUCCESS)
     goto quit;

  if (debug)
  {
    printf ("Host Name: %s\n", fi->HostName);
    printf ("Domain Name: %s\n", fi->DomainName);
    printf ("DNS Servers:\n"
            "    %s (primary)\n", fi->DnsServerList.IpAddress.String);
  }
  if (inet_addr(fi->DnsServerList.IpAddress.String) != INADDR_NONE &&
      left > ip_size)
  {
    ret += sprintf (ret, "%s,", fi->DnsServerList.IpAddress.String);
    left -= ret - ret_buf;
    count++;
  }

  for (i = 0, ipAddr = fi->DnsServerList.Next; ipAddr && left > ip_size;
       ipAddr = ipAddr->Next, i++)
  {
    if (inet_addr(ipAddr->IpAddress.String) != INADDR_NONE)
    {
       ret += sprintf (ret, "%s,", ipAddr->IpAddress.String);
       left -= ret - ret_buf;
       count++;
    }
    if (debug)
       printf ("    %s (secondary %d)\n", ipAddr->IpAddress.String, i+1);
  }

quit:
  if (handle)
     FreeLibrary (handle);

  if (debug && left <= ip_size)
     printf ("Too many nameservers. Truncating to %d addressess", count);
  if (ret > ret_buf)
     ret[-1] = '\0';
  return (count);
}
#endif

static int init_by_resolv_conf(ares_channel channel)
{
  char *line = NULL;
  int status = -1, nservers = 0, nsort = 0;
  struct server_state *servers = NULL;
  struct apattern *sortlist = NULL;

#ifdef WIN32

    /*
  NameServer info via IPHLPAPI (IP helper API):
    GetNetworkParams() should be the trusted source for this.
    Available in Win-98/2000 and later. If that fail, fall-back to
    registry information.

  NameServer Registry:

   On Windows 9X, the DNS server can be found in:
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\VxD\MSTCP\NameServer

        On Windows NT/2000/XP/2003:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\NameServer
        or
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DhcpNameServer
        or
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\{AdapterID}\
NameServer
        or
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\{AdapterID}\
DhcpNameServer
   */

  HKEY mykey;
  HKEY subkey;
  DWORD data_type;
  DWORD bytes;
  DWORD result;
  char  buf[256];

  if (channel->nservers > -1)  /* don't override ARES_OPT_SERVER */
     return ARES_SUCCESS;

  if (get_iphlpapi_dns_info(buf,sizeof(buf)) > 0)
  {
    status = config_nameserver(&servers, &nservers, buf);
    if (status == ARES_SUCCESS)
      goto okay;
  }

  if (IS_NT())
  {
    if (RegOpenKeyEx(
          HKEY_LOCAL_MACHINE, WIN_NS_NT_KEY, 0,
          KEY_READ, &mykey
          ) == ERROR_SUCCESS)
    {
      RegOpenKeyEx(mykey, "Interfaces", 0,
                   KEY_QUERY_VALUE|KEY_ENUMERATE_SUB_KEYS, &subkey);
      if (get_res_nt(mykey, NAMESERVER, &line))
      {
        status = config_nameserver(&servers, &nservers, line);
        free(line);
      }
      else if (get_res_nt(mykey, DHCPNAMESERVER, &line))
      {
        status = config_nameserver(&servers, &nservers, line);
        free(line);
      }
      /* Try the interfaces */
      else if (get_res_interfaces_nt(subkey, NAMESERVER, &line))
      {
        status = config_nameserver(&servers, &nservers, line);
        free(line);
      }
      else if (get_res_interfaces_nt(subkey, DHCPNAMESERVER, &line))
      {
        status = config_nameserver(&servers, &nservers, line);
        free(line);
      }
      RegCloseKey(subkey);
      RegCloseKey(mykey);
    }
  }
  else
  {
    if (RegOpenKeyEx(
          HKEY_LOCAL_MACHINE, WIN_NS_9X, 0,
          KEY_READ, &mykey
          ) == ERROR_SUCCESS)
    {
      if ((result = RegQueryValueEx(
             mykey, NAMESERVER, NULL, &data_type,
             NULL, &bytes
             )
            ) == ERROR_SUCCESS ||
          result == ERROR_MORE_DATA)
      {
        if (bytes)
        {
          line = (char *)malloc(bytes+1);
          if (RegQueryValueEx(mykey, NAMESERVER, NULL, &data_type,
                              (unsigned char *)line, &bytes) ==
              ERROR_SUCCESS)
          {
            status = config_nameserver(&servers, &nservers, line);
          }
          free(line);
        }
      }
    }
    RegCloseKey(mykey);
  }

  if (status == ARES_SUCCESS)
    status = ARES_EOF;

#elif defined(__riscos__)

  /* Under RISC OS, name servers are listed in the
     system variable Inet$Resolvers, space separated. */

  line = getenv("Inet$Resolvers");
  status = ARES_EOF;
  if (line) {
    char *resolvers = strdup(line), *pos, *space;

    if (!resolvers)
      return ARES_ENOMEM;

    pos = resolvers;
    do {
      space = strchr(pos, ' ');
      if (space)
        *space = 0;
      status = config_nameserver(&servers, &nservers, pos);
      if (status != ARES_SUCCESS)
        break;
      pos = space + 1;
    } while (space);

    if (status == ARES_SUCCESS)
      status = ARES_EOF;

    free(resolvers);
  }

#elif defined(WATT32)
  int i;

  sock_init();
  for (i = 0; def_nameservers[i]; i++)
      ;
  if (i == 0)
    return ARES_SUCCESS; /* use localhost DNS server */

  nservers = i;
  servers = calloc(sizeof(*servers), i);
  if (!servers)
     return ARES_ENOMEM;

  for (i = 0; def_nameservers[i]; i++)
      servers[i].addr.s_addr = htonl(def_nameservers[i]);
  status = ARES_EOF;

#else
  {
    char *p;
    FILE *fp;
    int linesize;

    fp = fopen(PATH_RESOLV_CONF, "r");
    if (!fp)
      return (errno == ENOENT) ? ARES_SUCCESS : ARES_EFILE;
    while ((status = ares__read_line(fp, &line, &linesize)) == ARES_SUCCESS)
    {
      if ((p = try_config(line, "domain")))
        status = config_domain(channel, p);
      else if ((p = try_config(line, "lookup")) && !channel->lookups)
        status = config_lookup(channel, p, "bind", "file");
      else if ((p = try_config(line, "search")))
        status = set_search(channel, p);
      else if ((p = try_config(line, "nameserver")) && channel->nservers == -1)
        status = config_nameserver(&servers, &nservers, p);
      else if ((p = try_config(line, "sortlist")) && channel->nsort == -1)
        status = config_sortlist(&sortlist, &nsort, p);
      else if ((p = try_config(line, "options")))
        status = set_options(channel, p);
      else
        status = ARES_SUCCESS;
      if (status != ARES_SUCCESS)
        break;
    }
    fclose(fp);

    if (!channel->lookups) {
      /* Many systems (Solaris, Linux, BSD's) use nsswitch.conf */
      fp = fopen("/etc/nsswitch.conf", "r");
      if (fp) {
        while ((status = ares__read_line(fp, &line, &linesize)) == ARES_SUCCESS)
        {
          if ((p = try_config(line, "hosts:")) && !channel->lookups)
            status = config_lookup(channel, p, "dns", "files");
        }
        fclose(fp);
      }
    }

    if (!channel->lookups) {
      /* Linux / GNU libc 2.x and possibly others have host.conf */
      fp = fopen("/etc/host.conf", "r");
      if (fp) {
        while ((status = ares__read_line(fp, &line, &linesize)) == ARES_SUCCESS)
        {
          if ((p = try_config(line, "order")) && !channel->lookups)
            status = config_lookup(channel, p, "bind", "hosts");
        }
        fclose(fp);
      }
    }

    if (!channel->lookups) {
      /* Tru64 uses /etc/svc.conf */
      fp = fopen("/etc/svc.conf", "r");
      if (fp) {
        while ((status = ares__read_line(fp, &line, &linesize)) == ARES_SUCCESS)
        {
          if ((p = try_config(line, "hosts=")) && !channel->lookups)
            status = config_lookup(channel, p, "bind", "local");
        }
        fclose(fp);
      }
    }

    if(line)
      free(line);
  }

#endif

  /* Handle errors. */
  if (status != ARES_EOF)
    {
      if (servers != NULL)
        free(servers);
      if (sortlist != NULL)
        free(sortlist);
      return status;
    }

  /* If we got any name server entries, fill them in. */
#ifdef WIN32
okay:
#endif
  if (servers)
    {
      channel->servers = servers;
      channel->nservers = nservers;
    }

  /* If we got any sortlist entries, fill them in. */
  if (sortlist)
    {
      channel->sortlist = sortlist;
      channel->nsort = nsort;
    }

  return ARES_SUCCESS;
}

static int init_by_defaults(ares_channel channel)
{
  char hostname[MAXHOSTNAMELEN + 1];

  if (channel->flags == -1)
    channel->flags = 0;
  if (channel->timeout == -1)
    channel->timeout = DEFAULT_TIMEOUT;
  if (channel->tries == -1)
    channel->tries = DEFAULT_TRIES;
  if (channel->ndots == -1)
    channel->ndots = 1;
  if (channel->udp_port == -1)
    channel->udp_port = htons(NAMESERVER_PORT);
  if (channel->tcp_port == -1)
    channel->tcp_port = htons(NAMESERVER_PORT);

  if (channel->nservers == -1)
    {
      /* If nobody specified servers, try a local named. */
      channel->servers = malloc(sizeof(struct server_state));
      if (!channel->servers)
        return ARES_ENOMEM;
      channel->servers[0].addr.s_addr = htonl(INADDR_LOOPBACK);
      channel->nservers = 1;
    }

  if (channel->ndomains == -1)
    {
      /* Derive a default domain search list from the kernel hostname,
       * or set it to empty if the hostname isn't helpful.
       */
      if (gethostname(hostname, sizeof(hostname)) == -1
          || !strchr(hostname, '.'))
        {
          channel->domains = malloc(0);
          channel->ndomains = 0;
        }
      else
        {
          channel->domains = malloc(sizeof(char *));
          if (!channel->domains)
            return ARES_ENOMEM;
          channel->ndomains = 0;
          channel->domains[0] = strdup(strchr(hostname, '.') + 1);
          if (!channel->domains[0])
            return ARES_ENOMEM;
          channel->ndomains = 1;
        }
    }

  if (channel->nsort == -1)
    {
      channel->sortlist = NULL;
      channel->nsort = 0;
    }

  if (!channel->lookups)
    {
      channel->lookups = strdup("fb");
      if (!channel->lookups)
        return ARES_ENOMEM;
    }

  return ARES_SUCCESS;
}

#ifndef WIN32
static int config_domain(ares_channel channel, char *str)
{
  char *q;

  /* Set a single search domain. */
  q = str;
  while (*q && !isspace((unsigned char)*q))
    q++;
  *q = 0;
  return set_search(channel, str);
}

static int config_lookup(ares_channel channel, const char *str,
                         const char *bindch, const char *filech)
{
  char lookups[3], *l;
  const char *p;

  /* Set the lookup order.  Only the first letter of each work
   * is relevant, and it has to be "b" for DNS or "f" for the
   * host file.  Ignore everything else.
   */
  l = lookups;
  p = str;
  while (*p)
    {
      if ((*p == *bindch || *p == *filech) && l < lookups + 2) {
        if (*p == *bindch) *l++ = 'b';
        else *l++ = 'f';
      }
      while (*p && !isspace((unsigned char)*p) && (*p != ','))
        p++;
      while (*p && (isspace((unsigned char)*p) || (*p == ',')))
        p++;
    }
  *l = 0;
  channel->lookups = strdup(lookups);
  return (channel->lookups) ? ARES_SUCCESS : ARES_ENOMEM;
}

#endif

static int config_nameserver(struct server_state **servers, int *nservers,
                             char *str)
{
  struct in_addr addr;
  struct server_state *newserv;
  /* On Windows, there may be more than one nameserver specified in the same
   * registry key, so we parse it as a space or comma seperated list.
   */
#ifdef WIN32
  char *p = str;
  char *begin = str;
  int more = 1;
  while (more)
  {
    more = 0;
    while (*p && !isspace(*p) && *p != ',')
      p++;

    if (*p)
    {
      *p = 0;
      more = 1;
    }

    /* Skip multiple spaces or trailing spaces */
    if (!*begin)
    {
      begin = ++p;
      continue;
    }

    /* This is the part that actually sets the nameserver */
    addr.s_addr = inet_addr(begin);
    if (addr.s_addr == INADDR_NONE)
      continue;
    newserv = realloc(*servers, (*nservers + 1) * sizeof(struct server_state));
    if (!newserv)
      return ARES_ENOMEM;
    newserv[*nservers].addr = addr;
    *servers = newserv;
    (*nservers)++;

    if (!more)
      break;
    begin = ++p;
  }
#else
  /* Add a nameserver entry, if this is a valid address. */
  addr.s_addr = inet_addr(str);
  if (addr.s_addr == INADDR_NONE)
    return ARES_SUCCESS;
  newserv = realloc(*servers, (*nservers + 1) * sizeof(struct server_state));
  if (!newserv)
    return ARES_ENOMEM;
  newserv[*nservers].addr = addr;
  *servers = newserv;
  (*nservers)++;
#endif
  return ARES_SUCCESS;
}

#ifndef WIN32
static int config_sortlist(struct apattern **sortlist, int *nsort,
                           const char *str)
{
  struct apattern pat;
  const char *q;

  /* Add sortlist entries. */
  while (*str && *str != ';')
    {
      int bits;
      char ipbuf[16], ipbufpfx[32];
      /* Find just the IP */
      q = str;
      while (*q && *q != '/' && *q != ';' && !isspace((unsigned char)*q))
        q++;
      memcpy(ipbuf, str, (int)(q-str));
      ipbuf[(int)(q-str)] = 0;
      /* Find the prefix */
      if (*q == '/')
        {
          const char *str2 = q+1;
          while (*q && *q != ';' && !isspace((unsigned char)*q))
            q++;
          memcpy(ipbufpfx, str, (int)(q-str));
          ipbufpfx[(int)(q-str)] = 0;
          str = str2;
        }
      else
        ipbufpfx[0] = 0;
      /* Lets see if it is CIDR */
      /* First we'll try IPv6 */
      if ((bits = ares_inet_net_pton(AF_INET6, ipbufpfx ? ipbufpfx : ipbuf,
                                     &pat.addr.addr6,
                                     sizeof(pat.addr.addr6))) > 0)
        {
          pat.type = PATTERN_CIDR;
          pat.mask.bits = bits;
          pat.family = AF_INET6;
          if (!sortlist_alloc(sortlist, nsort, &pat))
            return ARES_ENOMEM;
        }
      if (ipbufpfx &&
          (bits = ares_inet_net_pton(AF_INET, ipbufpfx, &pat.addr.addr4,
                                     sizeof(pat.addr.addr4))) > 0)
        {
          pat.type = PATTERN_CIDR;
          pat.mask.bits = bits;
          pat.family = AF_INET;
          if (!sortlist_alloc(sortlist, nsort, &pat))
            return ARES_ENOMEM;
        }
      /* See if it is just a regular IP */
      else if (ip_addr(ipbuf, (int)(q-str), &pat.addr.addr4) == 0)
        {
          if (ipbufpfx)
            {
              memcpy(ipbuf, str, (int)(q-str));
              ipbuf[(int)(q-str)] = 0;
              if (ip_addr(ipbuf, (int)(q - str), &pat.mask.addr.addr4) != 0)
                natural_mask(&pat);
            }
          else
            natural_mask(&pat);
          pat.family = AF_INET;
          pat.type = PATTERN_MASK;
          if (!sortlist_alloc(sortlist, nsort, &pat))
            return ARES_ENOMEM;
        }
      else
        {
          while (*q && *q != ';' && !isspace((unsigned char)*q))
            q++;
        }
      str = q;
      while (isspace((unsigned char)*str))
        str++;
    }

  return ARES_SUCCESS;
}
#endif

static int set_search(ares_channel channel, const char *str)
{
  int n;
  const char *p, *q;

  if(channel->ndomains != -1) {
    /* if we already have some domains present, free them first */
    for(n=0; n < channel->ndomains; n++)
      free(channel->domains[n]);
    free(channel->domains);
    channel->ndomains = -1;
  }

  /* Count the domains given. */
  n = 0;
  p = str;
  while (*p)
    {
      while (*p && !isspace((unsigned char)*p))
        p++;
      while (isspace((unsigned char)*p))
        p++;
      n++;
    }

  channel->domains = malloc(n * sizeof(char *));
  if (!channel->domains && n)
    return ARES_ENOMEM;

  /* Now copy the domains. */
  n = 0;
  p = str;
  while (*p)
    {
      channel->ndomains = n;
      q = p;
      while (*q && !isspace((unsigned char)*q))
        q++;
      channel->domains[n] = malloc(q - p + 1);
      if (!channel->domains[n])
        return ARES_ENOMEM;
      memcpy(channel->domains[n], p, q - p);
      channel->domains[n][q - p] = 0;
      p = q;
      while (isspace((unsigned char)*p))
        p++;
      n++;
    }
  channel->ndomains = n;

  return ARES_SUCCESS;
}

static int set_options(ares_channel channel, const char *str)
{
  const char *p, *q, *val;

  p = str;
  while (*p)
    {
      q = p;
      while (*q && !isspace((unsigned char)*q))
        q++;
      val = try_option(p, q, "ndots:");
      if (val && channel->ndots == -1)
        channel->ndots = atoi(val);
      val = try_option(p, q, "retrans:");
      if (val && channel->timeout == -1)
        channel->timeout = atoi(val);
      val = try_option(p, q, "retry:");
      if (val && channel->tries == -1)
        channel->tries = atoi(val);
      p = q;
      while (isspace((unsigned char)*p))
        p++;
    }

  return ARES_SUCCESS;
}

#ifndef WIN32
static char *try_config(char *s, const char *opt)
{
  size_t len;

  len = strlen(opt);
  if (strncmp(s, opt, len) != 0 || !isspace((unsigned char)s[len]))
    return NULL;
  s += len;
  while (isspace((unsigned char)*s))
    s++;
  return s;
}

#endif

static const char *try_option(const char *p, const char *q, const char *opt)
{
  size_t len = strlen(opt);
  return ((size_t)(q - p) > len && !strncmp(p, opt, len)) ? &p[len] : NULL;
}

#ifndef WIN32
static int sortlist_alloc(struct apattern **sortlist, int *nsort,
                          struct apattern *pat)
{
  struct apattern *newsort;
  newsort = realloc(*sortlist, (*nsort + 1) * sizeof(struct apattern));
  if (!newsort)
    return 0;
  newsort[*nsort] = *pat;
  *sortlist = newsort;
  (*nsort)++;
  return 1;
}

static int ip_addr(const char *ipbuf, int len, struct in_addr *addr)
{

  /* Four octets and three periods yields at most 15 characters. */
  if (len > 15)
    return -1;

  addr->s_addr = inet_addr(ipbuf);
  if (addr->s_addr == INADDR_NONE && strcmp(ipbuf, "255.255.255.255") != 0)
    return -1;
  return 0;
}

static void natural_mask(struct apattern *pat)
{
  struct in_addr addr;

  /* Store a host-byte-order copy of pat in a struct in_addr.  Icky,
   * but portable.
   */
  addr.s_addr = ntohl(pat->addr.addr4.s_addr);

  /* This is out of date in the CIDR world, but some people might
   * still rely on it.
   */
  if (IN_CLASSA(addr.s_addr))
    pat->mask.addr.addr4.s_addr = htonl(IN_CLASSA_NET);
  else if (IN_CLASSB(addr.s_addr))
    pat->mask.addr.addr4.s_addr = htonl(IN_CLASSB_NET);
  else
    pat->mask.addr.addr4.s_addr = htonl(IN_CLASSC_NET);
}
#endif
