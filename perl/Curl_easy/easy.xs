/* Perl interface for libcurl. Check out the file README for more info. */
/*  

Copyright (C) 2000, Daniel Stenberg, , et al.  
You may opt to use, copy, modify, merge, publish, distribute and/or 
sell copies of the Software, and permit persons to whom the 
Software is furnished to do so, under the terms of the MPL or
the MIT/X-derivate licenses. You may pick one of these licenses.                                             
*/

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <curl/curl.h>
#include <curl/easy.h>

#if (LIBCURL_VERSION_NUM<0x070702)
#define CURLOPT_HEADERFUNCTION 20079
#define header_callback_func write_callback_func
#else
#define header_callback_func writeheader_callback_func
#endif

/* Lists that can be set via curl_easy_setopt() */

static struct curl_slist *httpheader = NULL, *quote = NULL, *postquote = NULL;


/* Buffer and varname for option CURLOPT_ERRORBUFFER */

static char errbuf[CURL_ERROR_SIZE];
static char *errbufvarname = NULL;


/* Callback functions */

static SV *read_callback = NULL, *write_callback = NULL,
          *progress_callback = NULL, *passwd_callback = NULL,
	  *header_callback = NULL; 
	  /* *closepolicy_callback = NULL; */


/* For storing the content */

static char *contbuf = NULL, *bufptr = NULL;
static int bufsize = 32768, contlen = 0;


/* Internal options for this perl module */

#define USE_INTERNAL_VARS 0x01

static int internal_options = 0;


/* Setup these global vars */

static void init_globals(void)
{
    if (httpheader) curl_slist_free_all(httpheader);
    if (quote) curl_slist_free_all(quote);
    if (postquote) curl_slist_free_all(postquote);
    httpheader = quote = postquote = NULL;
    if (errbufvarname) free(errbufvarname);
    errbufvarname = NULL;
    if (contbuf == NULL) {
	contbuf = malloc(bufsize + 1);
    }
    bufptr = contbuf;
    *bufptr = '\0';
    contlen = 0;
    internal_options = 0;
}


/* Register a callback function */

static void register_callback(SV **callback, SV *function)
{
    if (*callback == NULL) {
	/* First time, create new SV */
	*callback = newSVsv(function);
    } else {
	/* Been there, done that. Just overwrite the SV */
	SvSetSV(*callback, function);
    }
}

/* generic fwrite callback, which decides which callback to call */
static size_t
fwrite_wrapper (const void *ptr,
		size_t size,
		size_t nmemb,
		void *stream,
		void *call_function)
{
    dSP;
    int count, status;
    SV *sv;

    if (call_function) {
	/* then we are doing a callback to perl */

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);

	if (stream == stdout) {
	    sv = newSViv(0);	/* FIXME: should cast stdout to GLOB somehow? */
	} else if (stream == NULL) {
            sv = &PL_sv_undef;
        } else {		/* its already an SV */
	    sv = stream;
	}

	if (ptr != NULL) {
	    XPUSHs(sv_2mortal(newSVpvn((char *)ptr, (STRLEN)(size * nmemb))));
	} else {
	    XPUSHs(sv_2mortal(newSVpv("", 0)));
	}
	XPUSHs(sv_2mortal(newSVsv(sv)));	/* CURLOPT_FILE SV* */
	PUTBACK;

	count = perl_call_sv((SV *) call_function, G_SCALAR);

	SPAGAIN;
	if (count != 1)
	    croak("Big trouble, perl_call_sv(write_callback) didn't return status\n");

	status = POPi;

	PUTBACK;

	FREETMPS;
	LEAVE;
	return status;

    } else {
	/* default to a normal 'fwrite' */
	/* stream could be a FILE * or an SV * */
        /* or NULL since libcurl-7.8.1pre3  */
	FILE *f;

	if (stream == stdout ||
            stream == NULL) { /* the only possible FILE ? Think so */
	    f = stream;
	} else {		/* its a GLOB */
	    f = IoIFP(sv_2io(stream));	/* may barf if not a GLOB */
	}

	if (f)
           return fwrite(ptr, size, nmemb, f);
	else
           return (size_t) size*nmemb;
    }
}

/* Write callback for calling a perl callback */
size_t
write_callback_func( const void *ptr, size_t size,
                                size_t nmemb, void *stream)
{
    return fwrite_wrapper(ptr,size,nmemb,stream,
        write_callback);
}

/* header callback for calling a perl callback */
size_t
writeheader_callback_func( const void *ptr, size_t size,
                              size_t nmemb, void *stream)
{
    return fwrite_wrapper(ptr,size,nmemb,stream,
        header_callback);
}

size_t
read_callback_func( void *ptr, size_t size,
                    size_t nmemb, void *stream)
{
    dSP ;

    int count;
    SV *sv;
    STRLEN len;
    size_t maxlen,mylen;
    char *p;

    maxlen = size*nmemb;

    if (read_callback) {
        /* we are doing a callback to perl */

        ENTER ;
        SAVETMPS ;
 
        PUSHMARK(SP) ;
	
        if (stream == stdin) {
            sv = newSViv(0); /* should cast stdin to GLOB somehow? */
        } else { /* its an SV */
            sv = stream;
        }
	
        XPUSHs(sv_2mortal(newSViv(maxlen))); /* send how many bytes please */
        XPUSHs(sv_2mortal(newSVsv(sv))); /* CURLOPT_INFILE SV*  */
        PUTBACK ;

        count = perl_call_sv(read_callback, G_SCALAR);
	 
        SPAGAIN;
        if (count != 1)
            croak("Big trouble, perl_call_sv(read_callback) didn't return data\n");

        sv = POPs;
        p = SvPV(sv,len);

        /* only allowed to return the number of bytes asked for */
        mylen = len<maxlen ? len : maxlen;
        memcpy(ptr,p,(size_t)mylen);
        PUTBACK ;
 
        FREETMPS ;
        LEAVE ;
        return (size_t) (mylen/size);
    } else {
       /* default to a normal 'fread' */
       /* stream could be a FILE * or an SV * */
       FILE *f;

       if (stream == stdin) { /* the only possible FILE ? Think so*/
           f = stream;
       } else { /* its a GLOB */
           f = IoIFP(sv_2io(stream)); /* may barf if not a GLOB */
       }

       return fread(ptr,size,nmemb,f);
    }
}

/* Porgress callback for calling a perl callback */

static int progress_callback_func(void *clientp, size_t dltotal, size_t dlnow,
    size_t ultotal, size_t ulnow)
{
    dSP;
    int count;

    ENTER;
    SAVETMPS;
    PUSHMARK(sp);
    if (clientp != NULL) {
	XPUSHs(sv_2mortal(newSVpv(clientp, 0)));
    } else {
	XPUSHs(sv_2mortal(newSVpv("", 0)));
    }
    XPUSHs(sv_2mortal(newSViv(dltotal)));
    XPUSHs(sv_2mortal(newSViv(dlnow)));
    XPUSHs(sv_2mortal(newSViv(ultotal)));
    XPUSHs(sv_2mortal(newSViv(ulnow)));
    PUTBACK;
    count = perl_call_sv(progress_callback, G_SCALAR);
    SPAGAIN;
    if (count != 1)
	croak("Big trouble, perl_call_sv(progress_callback) didn't return 1\n");
    count = POPi;
    PUTBACK;
    FREETMPS;
    LEAVE;
    return count;
}


/* Password callback for calling a perl callback */

static int passwd_callback_func(void *clientp, char *prompt, char *buffer,
    int buflen)
{
    dSP;
    int count;
    SV *sv;
    STRLEN len;
    size_t mylen;
    char *p;            

    ENTER;
    SAVETMPS;
    PUSHMARK(sp);
    if (clientp != NULL) {
        XPUSHs(sv_2mortal(newSVsv(clientp)));
    } else {
        XPUSHs(sv_2mortal(newSVpv("", 0)));
    }
    XPUSHs(sv_2mortal(newSVpv(prompt, 0)));
    XPUSHs(sv_2mortal(newSViv(buflen)));
    PUTBACK;
    count = perl_call_sv(passwd_callback, G_ARRAY);
    SPAGAIN;
    if (count != 2)
	croak("Big trouble, perl_call_sv(passwd_callback) didn't return status + data\n");

    sv = POPs;
    count = POPi;

    p = SvPV(sv,len);
 
    /* only allowed to return the number of bytes asked for */
    mylen = len<(buflen-1) ? len : (buflen-1);
    memcpy(buffer,p,mylen);
    buffer[buflen]=0; /* ensure C string terminates */

    PUTBACK;
    FREETMPS;
    LEAVE;
    return count;
}


#if 0
/* awaiting closepolicy prototype */
int 
closepolicy_callback_func(void *clientp)
{
   dSP;
   int argc, status;
   SV *pl_status;

   ENTER;
   SAVETMPS;

   PUSHMARK(SP);
   PUTBACK;

   argc = perl_call_sv(closepolicy_callback, G_SCALAR);
   SPAGAIN;

   if (argc != 1) {
      croak("Unexpected number of arguments returned from closefunction callback\n");
   }
   pl_status = POPs;
   status = SvTRUE(pl_status) ? 0 : 1;

   PUTBACK;
   FREETMPS;
   LEAVE;

   return status;
}
#endif



/* Internal write callback. Only used if USE_INTERNAL_VARS was specified */

static size_t internal_write_callback(char *data, size_t size, size_t num,
    FILE *fp)
{
    int i;

    size *= num;
    if ((contlen + size) >= bufsize) {
	bufsize *= 2;
	contbuf = realloc(contbuf, bufsize + 1);
	bufptr = contbuf + contlen;
    }
    contlen += size;
    for (i = 0; i < size; i++) {
	*bufptr++ = *data++;
    }
    *bufptr = '\0';
    return size;
}


static int
constant(char *name, int arg)
{
    errno = 0;
    if (strncmp(name, "CURLINFO_", 9) == 0) {
	name += 9;
	switch (*name) {
	case 'A':
	case 'B':
	case 'C':
	    if (strEQ(name, "CONNECT_TIME")) return CURLINFO_CONNECT_TIME;
	    if (strEQ(name, "CONTENT_LENGTH_DOWNLOAD")) return CURLINFO_CONTENT_LENGTH_DOWNLOAD;
	    if (strEQ(name, "CONTENT_LENGTH_UPLOAD")) return CURLINFO_CONTENT_LENGTH_UPLOAD;
	    break;
	case 'D':
	case 'E':
	    if (strEQ(name, "EFFECTIVE_URL")) return CURLINFO_EFFECTIVE_URL;
	    break;
	case 'F':
	    if (strEQ(name, "FILETIME")) return CURLINFO_FILETIME;
	    break;
	case 'G':
	case 'H':
	    if (strEQ(name, "HEADER_SIZE")) return CURLINFO_HEADER_SIZE;
	    if (strEQ(name, "HTTP_CODE")) return CURLINFO_HTTP_CODE;
	    break;
	case 'I':
	case 'J':
	case 'K':
	case 'L':
	case 'M':
	case 'N':
	    if (strEQ(name, "NAMELOOKUP_TIME")) return CURLINFO_NAMELOOKUP_TIME;
	    break;
	case 'O':
	case 'P':
	    if (strEQ(name, "PRETRANSFER_TIME")) return CURLINFO_PRETRANSFER_TIME;
	    break;
	case 'Q':
	case 'R':
	    if (strEQ(name, "REQUEST_SIZE")) return CURLINFO_REQUEST_SIZE;
	    break;
	case 'S':
	    if (strEQ(name, "SSL_VERIFYRESULT")) return CURLINFO_SSL_VERIFYRESULT;
	    break;
	case 'T':
	    if (strEQ(name, "SIZE_DOWNLOAD")) return CURLINFO_SIZE_DOWNLOAD;
	    if (strEQ(name, "SIZE_UPLOAD")) return CURLINFO_SIZE_UPLOAD;
	    if (strEQ(name, "SPEED_DOWNLOAD")) return CURLINFO_SPEED_DOWNLOAD;
	    if (strEQ(name, "SPEED_UPLOAD")) return CURLINFO_SPEED_UPLOAD;
	    if (strEQ(name, "TOTAL_TIME")) return CURLINFO_TOTAL_TIME;
	    break;
	case 'U':
	case 'V':
	case 'W':
	case 'X':
	case 'Y':
	case 'Z':
	    break;
	}
    }
    if (strncmp(name, "CURLOPT_", 8) == 0) {
	name += 8;
	switch (*name) {
#include "curlopt-constants.c"
	}
    }
    if (strEQ(name, "USE_INTERNAL_VARS")) return USE_INTERNAL_VARS;
    errno = EINVAL;
    return 0;
}


MODULE = Curl::easy		PACKAGE = Curl::easy		PREFIX = curl_easy_

int
constant(name,arg)
    char * name
    int arg


void *
curl_easy_init()
CODE:
    init_globals();
    RETVAL = curl_easy_init();
    curl_easy_setopt(RETVAL, CURLOPT_HEADERFUNCTION, header_callback_func);
    curl_easy_setopt(RETVAL, CURLOPT_WRITEFUNCTION, write_callback_func);
OUTPUT:
    RETVAL

char *
curl_easy_version()
CODE:
	RETVAL=curl_version();
OUTPUT:
	RETVAL

int
curl_easy_setopt(curl, option, value)
void * curl
int option
SV * value
CODE:
    if (option < CURLOPTTYPE_OBJECTPOINT) {
	/* This is an option specifying an integer value: */
	RETVAL = curl_easy_setopt(curl, option, (long)SvIV(value));
    } else if (option == CURLOPT_FILE || option == CURLOPT_INFILE ||
	    option == CURLOPT_WRITEHEADER || option == CURLOPT_PROGRESSDATA ||
	    option == CURLOPT_PASSWDDATA) {
	/* This is an option specifying an SV * value: */
	RETVAL = curl_easy_setopt(curl, option, newSVsv(ST(2)));
    } else if (option == CURLOPT_ERRORBUFFER) {
	/* Pass in variable name for storing error messages... */
	RETVAL = curl_easy_setopt(curl, option, errbuf);
	if (errbufvarname) free(errbufvarname);
	errbufvarname = strdup((char *)SvPV(value, PL_na));
    } else if (option == CURLOPT_WRITEFUNCTION || option ==
	    CURLOPT_READFUNCTION || option == CURLOPT_PROGRESSFUNCTION ||
	    option == CURLOPT_PASSWDFUNCTION || option == CURLOPT_HEADERFUNCTION) {
	/* This is an option specifying a callback function */
	switch (option) {
	case CURLOPT_WRITEFUNCTION:
	    register_callback(&write_callback, value);
	    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_func);
	    break;
	case CURLOPT_READFUNCTION:
	    register_callback(&read_callback, value);
	    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback_func);
	    break;
        case CURLOPT_HEADERFUNCTION:
            register_callback(&header_callback, value);
	    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback_func);	
	case CURLOPT_PROGRESSFUNCTION:
	    register_callback(&progress_callback, value);
	    curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress_callback_func);
	    break;
	case CURLOPT_PASSWDFUNCTION:
	    register_callback(&passwd_callback, value);
	    curl_easy_setopt(curl, CURLOPT_PASSWDFUNCTION, passwd_callback_func);
	    break;
        /* awaiting a prototype for the closepolicy function callback 
        case CURLOPT_CLOSEFUNCTION:
            register_callback(&closepolicy_callback, value);
            curl_easy_setopt(curl, CURLOPT_CLOSEFUNCTION, closepolicy_callback_func);
            break;
        */
	}
	RETVAL = -1;
    } else if (option == CURLOPT_HTTPHEADER || option == CURLOPT_QUOTE ||
	    option == CURLOPT_POSTQUOTE) {
	/* This is an option specifying a list of curl_slist structs: */
	AV *array = (AV *)SvRV(value);
	struct curl_slist **slist = NULL;
	/* We have to find out which list to use... */
	switch (option) {
	case CURLOPT_HTTPHEADER:
	    slist = &httpheader; break;
	case CURLOPT_QUOTE:
	    slist = &quote; break;
	case CURLOPT_POSTQUOTE:
	    slist = &postquote; break;
	}
        /* free any previous list */
        if (*slist) {
            curl_slist_free_all(*slist);
            *slist=NULL;
        }                                                                       
	/* ...store the values into it... */
	for (;;) {
	    SV *sv = av_shift(array);
	    int len = 0;
	    char *str = SvPV(sv, len);
	    if (len == 0) break;
	    *slist = curl_slist_append(*slist, str);
	}
	/* ...and pass the list into curl_easy_setopt() */
	RETVAL = curl_easy_setopt(curl, option, *slist);
    } else {
	/* This is an option specifying a char * value: */
	RETVAL = curl_easy_setopt(curl, option, SvPV(value, PL_na));
    }
OUTPUT:
    RETVAL


int
internal_setopt(option, value)
int option
int value
CODE:
    if (value == 1) {
	internal_options |= option;
    } else {
	internal_options &= !option;
    }
    RETVAL = 0;
OUTPUT:
    RETVAL


int
curl_easy_perform(curl)
void * curl 
CODE:
    if (internal_options & USE_INTERNAL_VARS) {
	/* Use internal callback which just stores the content into a buffer. */
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, internal_write_callback);
	curl_easy_setopt(curl, CURLOPT_HEADER, 1);
    }
    RETVAL = curl_easy_perform(curl);
    if (RETVAL && errbufvarname) {
	/* If an error occurred and a varname for error messages has been
	   specified, store the error message. */
	SV *sv = perl_get_sv(errbufvarname, TRUE | GV_ADDMULTI);
	sv_setpv(sv, errbuf);
    }
    if (!RETVAL && (internal_options & USE_INTERNAL_VARS)) {
	/* No error and internal variable for the content are to be used:
	   Split the data into headers and content and store them into
	   perl variables. */
	SV *head_sv = perl_get_sv("Curl::easy::headers", TRUE | GV_ADDMULTI);
	SV *cont_sv = perl_get_sv("Curl::easy::content", TRUE | GV_ADDMULTI);
	char *p = contbuf;
	int nl = 0, found = 0;
	while (p < bufptr) {
	    if (nl && (*p == '\n' || *p == '\r')) {
		/* found empty line, end of headers */
		*p++ = '\0';
		sv_setpv(head_sv, contbuf);
		while (*p == '\n' || *p == '\r') {
		    p++;
		}
		sv_setpv(cont_sv, p);
		found = 1;
		break;
	    }
	    nl = (*p == '\n');
	    p++;
	}
	if (!found) {
	    sv_setpv(head_sv, "");
	    sv_setpv(cont_sv, contbuf);
	}
    }
OUTPUT:
    RETVAL


int
curl_easy_getinfo(curl, option, value)
void * curl
int option
double value
CODE:
#ifdef __GNUC__
    /* a(void) warnig about unnused variable */
    (void) value;
#endif
    switch (option & CURLINFO_TYPEMASK) {
	case CURLINFO_STRING: {
	    char * value = (char *)SvPV(ST(2), PL_na);
	    RETVAL = curl_easy_getinfo(curl, option, &value);
	    sv_setpv(ST(2), value);
	    break;
	}
	case CURLINFO_LONG: {
	    long value = (long)SvIV(ST(2));
	    RETVAL = curl_easy_getinfo(curl, option, &value);
	    sv_setiv(ST(2), value);
	    break;
	}
	case CURLINFO_DOUBLE: {
	    double value = (double)SvNV(ST(2));
	    RETVAL = curl_easy_getinfo(curl, option, &value);
	    sv_setnv(ST(2), value);
	    break;
	}
	default: {
	    RETVAL = CURLE_BAD_FUNCTION_ARGUMENT;
	    break;
	}
    }
OUTPUT:
    RETVAL


int
curl_easy_cleanup(curl)
void * curl 
CODE:
    curl_easy_cleanup(curl);
    init_globals();
    RETVAL = 0;
OUTPUT:
    RETVAL

