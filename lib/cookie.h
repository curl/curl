#ifndef __COOKIE_H
#define __COOKIE_H

#include <stdio.h>
#ifdef WIN32
#include <time.h>
#else
#include <sys/time.h>
#endif

#include <curl/curl.h>

struct Cookie {
   struct Cookie *next; /* next in the chain */
   char *name;        /* <this> = value */
   char *value;       /* name = <this> */
   char *path;	      /* path = <this> */
   char *domain;      /* domain = <this> */
   time_t expires;    /* expires = <this> */
   char *expirestr;  /* the plain text version */
   bool secure;       /* whether the 'secure' keyword was used */
};

struct CookieInfo {
   /* linked list of cookies we know of */
   struct Cookie *cookies;

   char *filename; /* file we read from/write to */
};

/* This is the maximum line length we accept for a cookie line */
#define MAX_COOKIE_LINE 2048
#define MAX_COOKIE_LINE_TXT "2047"

/* This is the maximum length of a cookie name we deal with: */
#define MAX_NAME 256
#define MAX_NAME_TXT "255"

struct Cookie *cookie_add(struct CookieInfo *, bool, char *);
struct CookieInfo *cookie_init(char *);
struct Cookie *cookie_getlist(struct CookieInfo *, char *, char *, bool);
void cookie_freelist(struct Cookie *);
void cookie_cleanup(struct CookieInfo *);

#endif
