/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include <string.h>
#include <errno.h>

#define _REENTRANT

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <malloc.h>
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>	/* required for free() prototypes */
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>     /* for the close() proto */
#endif
#ifdef	VMS
#include <in.h>
#include <inet.h>
#include <stdlib.h>
#endif
#endif

#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif

#ifdef WIN32
#include <process.h>
#endif

#if (defined(NETWARE) && defined(__NOVELL_LIBC__))
#undef in_addr_t
#define in_addr_t unsigned long
#endif

#include "urldata.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "share.h"
#include "strerror.h"
#include "url.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#if defined(HAVE_INET_NTOA_R) && !defined(HAVE_INET_NTOA_R_DECL)
#include "inet_ntoa_r.h"
#endif

#include "memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/***********************************************************************
 * Only for plain-ipv4 builds
 **********************************************************************/
#ifdef CURLRES_IPV4 /* plain ipv4 code coming up */

/*
 * This is a wrapper function for freeing name information in a protocol
 * independent way. This takes care of using the appropriate underlying
 * function.
 */
void Curl_freeaddrinfo(Curl_addrinfo *p)
{
  free(p); /* works fine for the ARES case too */
}

/*
 * Curl_ipvalid() checks what CURL_IPRESOLVE_* requirements that might've
 * been set and returns TRUE if they are OK.
 */
bool Curl_ipvalid(struct SessionHandle *data)
{
  if(data->set.ip_version == CURL_IPRESOLVE_V6)
    /* an ipv6 address was requested and we can't get/use one */
    return FALSE;

  return TRUE; /* OK, proceed */
}

/*
 * Curl_ip2addr() takes a 32bit ipv4 internet address as input parameter
 * together with a pointer to the string version of the address, and it
 * retruns a malloc()ed version of a hostent struct filled in correctly with
 * information for this address/host.
 *
 * The input parameters ARE NOT checked for validity but they are expected
 * to have been checked already when this is called.
 */
Curl_addrinfo *Curl_ip2addr(in_addr_t num, char *hostname)
{
  struct hostent *h;
  struct in_addr *addrentry;
  struct namebuf {
    struct hostent hostentry;
    char *h_addr_list[2];
    struct in_addr addrentry;
    char h_name[16]; /* 123.123.123.123 = 15 letters is maximum */
  } *buf = (struct namebuf *)malloc(sizeof(struct namebuf));

  if(!buf)
    return NULL; /* major failure */

  h = &buf->hostentry;
  h->h_addr_list = &buf->h_addr_list[0];
  addrentry = &buf->addrentry;
  addrentry->s_addr = num;
  h->h_addr_list[0] = (char*)addrentry;
  h->h_addr_list[1] = NULL;
  h->h_addrtype = AF_INET;
  h->h_length = sizeof(*addrentry);
  h->h_name = &buf->h_name[0];
  h->h_aliases = NULL;

  /* Now store the dotted version of the address */
  snprintf(h->h_name, 16, "%s", hostname);

  return h;
}

#ifdef CURLRES_SYNCH /* the functions below are for synchronous resolves */

/*
 * Curl_getaddrinfo() - the ipv4 synchronous version.
 *
 * The original code to this function was once stolen from the Dancer source
 * code, written by Bjorn Reese, it has since been patched and modified
 * considerably.
 *
 * gethostbyname_r() is the thread-safe version of the gethostbyname()
 * function. When we build for plain IPv4, we attempt to use this
 * function. There are _three_ different gethostbyname_r() versions, and we
 * detect which one this platform supports in the configure script and set up
 * the HAVE_GETHOSTBYNAME_R_3, HAVE_GETHOSTBYNAME_R_5 or
 * HAVE_GETHOSTBYNAME_R_6 defines accordingly. Note that HAVE_GETADDRBYNAME
 * has the corresponding rules. This is primarily on *nix. Note that some unix
 * flavours have thread-safe versions of the plain gethostbyname() etc.
 *
 */
Curl_addrinfo *Curl_getaddrinfo(struct connectdata *conn,
                                char *hostname,
                                int port,
                                int *waitp)
{
  struct hostent *h = NULL;
  in_addr_t in;
  struct SessionHandle *data = conn->data;
  (void)port; /* unused in IPv4 code */

  *waitp = 0; /* don't wait, we act synchronously */

  in=inet_addr(hostname);
  if (in != CURL_INADDR_NONE)
    /* This is a dotted IP address 123.123.123.123-style */
    return Curl_ip2addr(in, hostname);

#if defined(HAVE_GETHOSTBYNAME_R)
  /*
   * gethostbyname_r() is the preferred resolve function for many platforms.
   * Since there are three different versions of it, the following code is
   * somewhat #ifdef-ridden.
   */
  else {
    int h_errnop;
    int res=ERANGE;
    int step_size=200;
    int *buf = (int *)calloc(CURL_HOSTENT_SIZE, 1);
    if(!buf)
      return NULL; /* major failure */
    /*
     * The clearing of the buffer is a workaround for a gethostbyname_r bug in
     * qnx nto and it is also _required_ for some of these functions on some
     * platforms.
     */

#ifdef HAVE_GETHOSTBYNAME_R_5
    /* Solaris, IRIX and more */
    (void)res; /* prevent compiler warning */
    while(!h) {
      h = gethostbyname_r(hostname,
                          (struct hostent *)buf,
                          (char *)buf + sizeof(struct hostent),
                          step_size - sizeof(struct hostent),
                          &h_errnop);

      /* If the buffer is too small, it returns NULL and sets errno to
       * ERANGE. The errno is thread safe if this is compiled with
       * -D_REENTRANT as then the 'errno' variable is a macro defined to get
       * used properly for threads.
       */

      if(h || (errno != ERANGE))
        break;
      
      step_size+=200;
    }

#ifdef CURLDEBUG
    infof(data, "gethostbyname_r() uses %d bytes\n", step_size);
#endif

    if(h) {
      int offset;
      h=(struct hostent *)realloc(buf, step_size);
      offset=(long)h-(long)buf;
      Curl_hostent_relocate(h, offset);
      buf=(int *)h;
    }
    else
#endif /* HAVE_GETHOSTBYNAME_R_5 */
#ifdef HAVE_GETHOSTBYNAME_R_6
    /* Linux */
    do {
      res=gethostbyname_r(hostname,
			  (struct hostent *)buf,
			  (char *)buf + sizeof(struct hostent),
			  step_size - sizeof(struct hostent),
			  &h, /* DIFFERENCE */
			  &h_errnop);
      /* Redhat 8, using glibc 2.2.93 changed the behavior. Now all of a
       * sudden this function returns EAGAIN if the given buffer size is too
       * small. Previous versions are known to return ERANGE for the same
       * problem.
       *
       * This wouldn't be such a big problem if older versions wouldn't
       * sometimes return EAGAIN on a common failure case. Alas, we can't
       * assume that EAGAIN *or* ERANGE means ERANGE for any given version of
       * glibc.
       *
       * For now, we do that and thus we may call the function repeatedly and
       * fail for older glibc versions that return EAGAIN, until we run out of
       * buffer size (step_size grows beyond CURL_HOSTENT_SIZE).
       *
       * If anyone has a better fix, please tell us!
       *
       * -------------------------------------------------------------------
       *
       * On October 23rd 2003, Dan C dug up more details on the mysteries of
       * gethostbyname_r() in glibc:
       *
       * In glibc 2.2.5 the interface is different (this has also been
       * discovered in glibc 2.1.1-6 as shipped by Redhat 6). What I can't
       * explain, is that tests performed on glibc 2.2.4-34 and 2.2.4-32
       * (shipped/upgraded by Redhat 7.2) don't show this behavior!
       *
       * In this "buggy" version, the return code is -1 on error and 'errno'
       * is set to the ERANGE or EAGAIN code. Note that 'errno' is not a
       * thread-safe variable.
       */

      if(((ERANGE == res) || (EAGAIN == res)) ||
         ((res<0) && ((ERANGE == errno) || (EAGAIN == errno))))
	step_size+=200;
      else
        break;
    } while(step_size <= CURL_HOSTENT_SIZE);

    if(!h) /* failure */
      res=1;
    
#ifdef CURLDEBUG
    infof(data, "gethostbyname_r() uses %d bytes\n", step_size);
#endif
    if(!res) {
      int offset;
      h=(struct hostent *)realloc(buf, step_size);
      offset=(long)h-(long)buf;
      Curl_hostent_relocate(h, offset);
      buf=(int *)h;
    }
    else
#endif/* HAVE_GETHOSTBYNAME_R_6 */
#ifdef HAVE_GETHOSTBYNAME_R_3
    /* AIX, Digital Unix/Tru64, HPUX 10, more? */

    /* For AIX 4.3 or later, we don't use gethostbyname_r() at all, because of
     * the plain fact that it does not return unique full buffers on each
     * call, but instead several of the pointers in the hostent structs will
     * point to the same actual data! This have the unfortunate down-side that
     * our caching system breaks down horribly. Luckily for us though, AIX 4.3
     * and more recent versions have a "completely thread-safe"[*] libc where
     * all the data is stored in thread-specific memory areas making calls to
     * the plain old gethostbyname() work fine even for multi-threaded
     * programs.
     *
     * This AIX 4.3 or later detection is all made in the configure script.
     *
     * Troels Walsted Hansen helped us work this out on March 3rd, 2003.
     *
     * [*] = much later we've found out that it isn't at all "completely
     * thread-safe", but at least the gethostbyname() function is.
     */

    if(CURL_HOSTENT_SIZE >=
       (sizeof(struct hostent)+sizeof(struct hostent_data))) {

      /* August 22nd, 2000: Albert Chin-A-Young brought an updated version
       * that should work! September 20: Richard Prescott worked on the buffer
       * size dilemma.
       */

      res = gethostbyname_r(hostname,
                            (struct hostent *)buf,
                            (struct hostent_data *)((char *)buf +
                                                    sizeof(struct hostent)));
      h_errnop= errno; /* we don't deal with this, but set it anyway */
    }
    else
      res = -1; /* failure, too smallish buffer size */

    if(!res) { /* success */

      h = (struct hostent*)buf; /* result expected in h */

      /* This is the worst kind of the different gethostbyname_r() interfaces.
       * Since we don't know how big buffer this particular lookup required,
       * we can't realloc down the huge alloc without doing closer analysis of
       * the returned data. Thus, we always use CURL_HOSTENT_SIZE for every
       * name lookup. Fixing this would require an extra malloc() and then
       * calling Curl_addrinfo_copy() that subsequent realloc()s down the new
       * memory area to the actually used amount.
       */
    }    
    else
#endif /* HAVE_GETHOSTBYNAME_R_3 */
      {
      infof(data, "gethostbyname_r(2) failed for %s\n", hostname);
      h = NULL; /* set return code to NULL */
      free(buf);
    }
#else /* HAVE_GETHOSTBYNAME_R */
    /*
     * Here is code for platforms that don't have gethostbyname_r() or for
     * which the gethostbyname() is the preferred() function.
     */
  else {
    h = gethostbyname(hostname);
    if (!h)
      infof(data, "gethostbyname(2) failed for %s\n", hostname);
    else {
      /*
       * Copy the hostent struct right here, as the static one we got a
       * pointer to might get removed when we don't want/expect that. Windows
       * (other platforms?) also doesn't allow passing of the returned data
       * between threads, which thus the copying here them allows the app to
       * do.
       */
      h = Curl_addrinfo_copy(h);
    }
#endif /*HAVE_GETHOSTBYNAME_R */
  }

  return h;
}

#endif /* CURLRES_SYNCH */

#endif /* CURLRES_IPV4 */
