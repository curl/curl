
/***


RECEIVING COOKIE INFORMATION
============================

struct CookieInfo *cookie_init(char *file);
	
	Inits a cookie struct to store data in a local file. This is always
	called before any cookies are set.

int cookies_set(struct CookieInfo *cookie, char *cookie_line);

	The 'cookie_line' parameter is a full "Set-cookie:" line as
	received from a server.

	The function need to replace previously stored lines that this new
	line superceeds.

	It may remove lines that are expired.

	It should return an indication of success/error.


SENDING COOKIE INFORMATION
==========================

struct Cookies *cookie_getlist(struct CookieInfo *cookie,
                               char *host, char *path, bool secure);

	For a given host and path, return a linked list of cookies that
	the client should send to the server if used now. The secure
	boolean informs the cookie if a secure connection is achieved or
	not.

	It shall only return cookies that haven't expired.

    
Example set of cookies:
    
    Set-cookie: PRODUCTINFO=webxpress; domain=.fidelity.com; path=/; secure
    Set-cookie: PERSONALIZE=none;expires=Monday, 13-Jun-1988 03:04:55 GMT;
    domain=.fidelity.com; path=/ftgw; secure
    Set-cookie: FidHist=none;expires=Monday, 13-Jun-1988 03:04:55 GMT;
    domain=.fidelity.com; path=/; secure
    Set-cookie: FidOrder=none;expires=Monday, 13-Jun-1988 03:04:55 GMT;
    domain=.fidelity.com; path=/; secure
    Set-cookie: DisPend=none;expires=Monday, 13-Jun-1988 03:04:55 GMT;
    domain=.fidelity.com; path=/; secure
    Set-cookie: FidDis=none;expires=Monday, 13-Jun-1988 03:04:55 GMT;
    domain=.fidelity.com; path=/; secure
    Set-cookie:
    Session_Key@6791a9e0-901a-11d0-a1c8-9b012c88aa77=none;expires=Monday,
    13-Jun-1988 03:04:55 GMT; domain=.fidelity.com; path=/; secure
****/

#include "setup.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "cookie.h"
#include "getdate.h"
#include "strequal.h"

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

/****************************************************************************
 *
 * cookie_add()
 *
 * Add a single cookie line to the cookie keeping object.
 *
 ***************************************************************************/

struct Cookie *cookie_add(struct CookieInfo *c,
                          bool httpheader, /* TRUE if HTTP header-style line */
                          char *lineptr) /* first non-space of the line */
{
  struct Cookie *clist;
  char what[MAX_COOKIE_LINE];
  char name[MAX_NAME];
  char *ptr;
  char *semiptr;
  struct Cookie *co;
  time_t now = time(NULL);
  bool replace_old = FALSE;

  /* First, alloc and init a new struct for it */
  co = (struct Cookie *)malloc(sizeof(struct Cookie));
  if(!co)
    return NULL; /* bail out if we're this low on memory */

  /* clear the whole struct first */
  memset(co, 0, sizeof(struct Cookie));
	    
  if(httpheader) {
    /* This line was read off a HTTP-header */

    semiptr=strchr(lineptr, ';'); /* first, find a semicolon */
    ptr = lineptr;
    do {
      if(semiptr)
        *semiptr='\0'; /* zero terminate for a while */
      /* we have a <what>=<this> pair or a 'secure' word here */
      if(strchr(ptr, '=')) {
        name[0]=what[0]=0; /* init the buffers */
        if(1 <= sscanf(ptr, "%" MAX_NAME_TXT "[^=]=%"
                       MAX_COOKIE_LINE_TXT "[^\r\n]",
                       name, what)) {
          /* this is a legal <what>=<this> pair */
          if(strequal("path", name)) {
            co->path=strdup(what);
          }
          else if(strequal("domain", name)) {
            co->domain=strdup(what);
          }
          else if(strequal("version", name)) {
            co->version=strdup(what);
          }
          else if(strequal("max-age", name)) {
            /* Defined in RFC2109:

               Optional.  The Max-Age attribute defines the lifetime of the
               cookie, in seconds.  The delta-seconds value is a decimal non-
               negative integer.  After delta-seconds seconds elapse, the
               client should discard the cookie.  A value of zero means the
               cookie should be discarded immediately.

             */
            co->maxage = strdup(what);
            co->expires =
              atoi((*co->maxage=='\"')?&co->maxage[1]:&co->maxage[0]);
          }
          else if(strequal("expires", name)) {
            co->expirestr=strdup(what);
            co->expires = curl_getdate(what, &now);
          }
          else if(!co->name) {
            co->name = strdup(name);
            co->value = strdup(what);
          }
          else
            ;/* this is the second (or more) name we don't know
                about! */
        }
        else {
          /* this is an "illegal" <what>=<this> pair */
        }
      }
      else {
        if(sscanf(ptr, "%" MAX_COOKIE_LINE_TXT "[^\r\n]",
                  what)) {
          if(strequal("secure", what))
            co->secure = TRUE;
          else
            ; /* unsupported keyword without assign! */
        }
      }
      if(!semiptr)
        continue; /* we already know there are no more cookies */

      *semiptr=';'; /* put the semicolon back */
      ptr=semiptr+1;
      while(ptr && *ptr && isspace((int)*ptr))
        ptr++;
      semiptr=strchr(ptr, ';'); /* now, find the next semicolon */
    } while(semiptr);
  }
  else {
    /* This line is NOT a HTTP header style line, we do offer support for
       reading the odd netscape cookies-file format here */
    char *firstptr;
    int fields;

    if(lineptr[0]=='#') {
      /* don't even try the comments */
      free(co);
      return NULL;
    }
    /* strip off the possible end-of-line characters */
    ptr=strchr(lineptr, '\r');
    if(ptr)
      *ptr=0; /* clear it */
    ptr=strchr(lineptr, '\n');
    if(ptr)
      *ptr=0; /* clear it */

    firstptr=strtok(lineptr, "\t"); /* first tokenize it on the TAB */

    /* Here's a quick check to eliminate normal HTTP-headers from this */
    if(!firstptr || strchr(firstptr, ':')) {
      free(co);
      return NULL;
    }

    /* Now loop through the fields and init the struct we already have
       allocated */
    for(ptr=firstptr, fields=0; ptr; ptr=strtok(NULL, "\t"), fields++) {
      switch(fields) {
      case 0:
        co->domain = strdup(ptr);
        break;
      case 1:
        /* what _is_ this field for? */
        break;
      case 2:
        co->path = strdup(ptr);
        break;
      case 3:
        co->secure = strequal(ptr, "TRUE");
        break;
      case 4:
        co->expires = atoi(ptr);
        break;
      case 5:
        co->name = strdup(ptr);
        break;
      case 6:
        co->value = strdup(ptr);
        break;
      }
    }

    if(7 != fields) {
      /* we did not find the sufficient number of fields to recognize this
         as a valid line, abort and go home */

      if(co->domain)
        free(co->domain);
      if(co->path)
        free(co->path);
      if(co->name)
        free(co->name);
      if(co->value)
        free(co->value);

      free(co);
      return NULL;
    }

  }

  /* now, we have parsed the incoming line, we must now check if this
     superceeds an already existing cookie, which it may if the previous have
     the same domain and path as this */

  clist = c->cookies;
  replace_old = FALSE;
  while(clist) {
    if(strequal(clist->name, co->name)) {
      /* the names are identical */

      if(clist->domain && co->domain) {
        if(strequal(clist->domain, co->domain))
          replace_old=TRUE;
      }
      else if(!clist->domain && !co->domain)
        replace_old = TRUE;

      if(replace_old) {
        /* the domains were identical */

        if(clist->path && co->path) {
          if(strequal(clist->path, co->path)) {
            replace_old = TRUE;
          }
          else
            replace_old = FALSE;
        }
        else if(!clist->path && !co->path)
          replace_old = TRUE;
        else
          replace_old = FALSE;
        
      }

      if(replace_old) {
        co->next = clist->next; /* get the next-pointer first */

        /* then free all the old pointers */
        if(clist->name)
          free(clist->name);
        if(clist->value)
          free(clist->value);
        if(clist->domain)
          free(clist->domain);
        if(clist->path)
          free(clist->path);
        if(clist->expirestr)
          free(clist->expirestr);

        if(clist->version)
          free(clist->version);
        if(clist->maxage)
          free(clist->maxage);

        *clist = *co;  /* then store all the new data */
      }

    }
    clist = clist->next;
  }

  if(!replace_old) {

    /* first, point to our "next" */
    co->next = c->cookies;
    /* then make ourselves first in the list */
    c->cookies = co;
  }
  return co;
}

/*****************************************************************************
 *
 * cookie_init()
 *
 * Inits a cookie struct to read data from a local file. This is always
 * called before any cookies are set. File may be NULL.
 *
 ****************************************************************************/
struct CookieInfo *cookie_init(char *file)
{
  char line[MAX_COOKIE_LINE];
  struct CookieInfo *c;
  FILE *fp;
  bool fromfile=TRUE;
  
  c = (struct CookieInfo *)malloc(sizeof(struct CookieInfo));
  if(!c)
    return NULL; /* failed to get memory */
  memset(c, 0, sizeof(struct CookieInfo));
  c->filename = strdup(file?file:"none"); /* copy the name just in case */

  if(strequal(file, "-")) {
    fp = stdin;
    fromfile=FALSE;
  }
  else
    fp = file?fopen(file, "r"):NULL;

  if(fp) {
    while(fgets(line, MAX_COOKIE_LINE, fp)) {
      if(strnequal("Set-Cookie:", line, 11)) {
        /* This is a cookie line, get it! */
        char *lineptr=&line[11];
        while(*lineptr && isspace((int)*lineptr))
          lineptr++;

        cookie_add(c, TRUE, lineptr);
      }
      else {
        /* This might be a netscape cookie-file line, get it! */
        char *lineptr=line;
        while(*lineptr && isspace((int)*lineptr))
          lineptr++;

        cookie_add(c, FALSE, lineptr);
      }
    }
    if(fromfile)
      fclose(fp);
  }

  return c;
}

/*****************************************************************************
 *
 * cookie_getlist()
 *
 * For a given host and path, return a linked list of cookies that the
 * client should send to the server if used now. The secure boolean informs
 * the cookie if a secure connection is achieved or not.
 *
 * It shall only return cookies that haven't expired.
 *
 ****************************************************************************/

struct Cookie *cookie_getlist(struct CookieInfo *c,
			      char *host, char *path, bool secure)
{
   struct Cookie *newco;
   struct Cookie *co;
   time_t now = time(NULL);
   int hostlen=strlen(host);
   int domlen;

   struct Cookie *mainco=NULL;

   if(!c || !c->cookies)
      return NULL; /* no cookie struct or no cookies in the struct */

   co = c->cookies;

   while(co) {
      /* only process this cookie if it is not expired or had no expire
	 date AND that if the cookie requires we're secure we must only
	 continue if we are! */
     if( (co->expires<=0 || (co->expires> now)) &&
         (co->secure?secure:TRUE) ) {

	 /* now check if the domain is correct */
	 domlen=co->domain?strlen(co->domain):0;
	 if(!co->domain ||
	    ((domlen<hostlen) &&
	     strequal(host+(hostlen-domlen), co->domain)) ) {
	    /* the right part of the host matches the domain stuff in the
	       cookie data */

	    /* now check the left part of the path with the cookies path
	       requirement */
	    if(!co->path ||
	       strnequal(path, co->path, strlen(co->path))) {

	       /* and now, we know this is a match and we should create an
		  entry for the return-linked-list */

	       newco = (struct Cookie *)malloc(sizeof(struct Cookie));
	       if(newco) {
		  /* first, copy the whole source cookie: */
		  memcpy(newco, co, sizeof(struct Cookie));

		  /* then modify our next */
		  newco->next = mainco;

		  /* point the main to us */
		  mainco = newco;
	       }
	    }
	 }
      }
      co = co->next;
   }

   return mainco; /* return the new list */
}


/*****************************************************************************
 *
 * cookie_freelist()
 *
 * Free a list previously returned by cookie_getlist();
 *
 ****************************************************************************/

void cookie_freelist(struct Cookie *co)
{
   struct Cookie *next;
   if(co) {
      while(co) {
	 next = co->next;
	 free(co); /* we only free the struct since the "members" are all
		      just copied! */
	 co = next;
      }
   }
}

/*****************************************************************************
 *
 * cookie_cleanup()
 *
 * Free a "cookie object" previous created with cookie_init().
 *
 ****************************************************************************/
void cookie_cleanup(struct CookieInfo *c)
{
   struct Cookie *co;
   struct Cookie *next;
   if(c) {
      if(c->filename)
	 free(c->filename);
      co = c->cookies;

      while(co) {
	 if(co->name)
	    free(co->name);
	 if(co->value)
	    free(co->value);
	 if(co->domain)
	    free(co->domain);
	 if(co->path)
	    free(co->path);
	 if(co->expirestr)
	    free(co->expirestr);

	 if(co->version)
	    free(co->version);
	 if(co->maxage)
	    free(co->maxage);

	 next = co->next;
	 free(co);
	 co = next;
      }
      free(c); /* free the base struct as well */
   }
}

