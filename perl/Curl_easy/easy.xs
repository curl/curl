/* Perl interface for libcurl. Check out the file README for more info. */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <curl/curl.h>
#include <curl/easy.h>


/* Buffer and varname for option CURLOPT_ERRORBUFFER */

static char errbuf[CURL_ERROR_SIZE];
static char *errbufvarname = NULL;


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
	case 'D':
	    if (strEQ(name, "CONNECT_TIME")) return CURLINFO_CONNECT_TIME;
	    break;
	case 'E':
	case 'F':
	    if (strEQ(name, "EFFECTIVE_URL")) return CURLINFO_EFFECTIVE_URL;
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
	case 'A':
	case 'B':
	    if (strEQ(name, "AUTOREFERER")) return CURLOPT_AUTOREFERER;
	    break;
	case 'C':
	case 'D':
	    if (strEQ(name, "COOKIE")) return CURLOPT_COOKIE;
	    if (strEQ(name, "COOKIEFILE")) return CURLOPT_COOKIEFILE;
	    if (strEQ(name, "CRLF")) return CURLOPT_CRLF;
	    if (strEQ(name, "CUSTOMREQUEST")) return CURLOPT_CUSTOMREQUEST;
	    break;
	case 'E':
	case 'F':
	    if (strEQ(name, "ERRORBUFFER")) return CURLOPT_ERRORBUFFER;
	    if (strEQ(name, "FAILONERROR")) return CURLOPT_FAILONERROR;
	    if (strEQ(name, "FILE")) return CURLOPT_FILE;
	    if (strEQ(name, "FOLLOWLOCATION")) return CURLOPT_FOLLOWLOCATION;
	    if (strEQ(name, "FTPAPPEND")) return CURLOPT_FTPAPPEND;
	    if (strEQ(name, "FTPASCII")) return CURLOPT_FTPASCII;
	    if (strEQ(name, "FTPLISTONLY")) return CURLOPT_FTPLISTONLY;
	    if (strEQ(name, "FTPPORT")) return CURLOPT_FTPPORT;
	    break;
	case 'G':
	case 'H':
	    if (strEQ(name, "HEADER")) return CURLOPT_HEADER;
	    if (strEQ(name, "HTTPHEADER")) return CURLOPT_HTTPHEADER;
	    if (strEQ(name, "HTTPPOST")) return CURLOPT_HTTPPOST;
	    if (strEQ(name, "HTTPPROXYTUNNEL")) return CURLOPT_HTTPPROXYTUNNEL;
	    if (strEQ(name, "HTTPREQUEST")) return CURLOPT_HTTPREQUEST;
	    break;
	case 'I':
	case 'J':
	    if (strEQ(name, "INFILE")) return CURLOPT_INFILE;
	    if (strEQ(name, "INFILESIZE")) return CURLOPT_INFILESIZE;
	    if (strEQ(name, "INTERFACE")) return CURLOPT_INTERFACE;
	    break;
	case 'K':
	case 'L':
	    if (strEQ(name, "KRB4LEVEL")) return CURLOPT_KRB4LEVEL;
	    if (strEQ(name, "LOW_SPEED_LIMIT")) return CURLOPT_LOW_SPEED_LIMIT;
	    if (strEQ(name, "LOW_SPEED_TIME")) return CURLOPT_LOW_SPEED_TIME;
	    break;
	case 'M':
	case 'N':
	    if (strEQ(name, "MUTE")) return CURLOPT_MUTE;
	    if (strEQ(name, "NETRC")) return CURLOPT_NETRC;
	    if (strEQ(name, "NOBODY")) return CURLOPT_NOBODY;
	    if (strEQ(name, "NOPROGRESS")) return CURLOPT_NOPROGRESS;
	    if (strEQ(name, "NOTHING")) return CURLOPT_NOTHING;
	    break;
	case 'O':
	case 'P':
	    if (strEQ(name, "PORT")) return CURLOPT_PORT;
	    if (strEQ(name, "POST")) return CURLOPT_POST;
	    if (strEQ(name, "POSTFIELDS")) return CURLOPT_POSTFIELDS;
	    if (strEQ(name, "POSTFIELDSIZE")) return CURLOPT_POSTFIELDSIZE;
	    if (strEQ(name, "POSTQUOTE")) return CURLOPT_POSTQUOTE;
	    if (strEQ(name, "PROGRESSDATA")) return CURLOPT_PROGRESSDATA;
	    if (strEQ(name, "PROGRESSFUNCTION")) return CURLOPT_PROGRESSFUNCTION;
	    if (strEQ(name, "PROXY")) return CURLOPT_PROXY;
	    if (strEQ(name, "PROXYPORT")) return CURLOPT_PROXYPORT;
	    if (strEQ(name, "PROXYUSERPWD")) return CURLOPT_PROXYUSERPWD;
	    if (strEQ(name, "PUT")) return CURLOPT_PUT;
	    break;
	case 'Q':
	case 'R':
	    if (strEQ(name, "QUOTE")) return CURLOPT_QUOTE;
	    if (strEQ(name, "RANGE")) return CURLOPT_RANGE;
	    if (strEQ(name, "READFUNCTION")) return CURLOPT_READFUNCTION;
	    if (strEQ(name, "REFERER")) return CURLOPT_REFERER;
	    if (strEQ(name, "RESUME_FROM")) return CURLOPT_RESUME_FROM;
	    break;
	case 'S':
	case 'T':
	    if (strEQ(name, "SSLCERT")) return CURLOPT_SSLCERT;
	    if (strEQ(name, "SSLCERTPASSWD")) return CURLOPT_SSLCERTPASSWD;
	    if (strEQ(name, "SSLVERSION")) return CURLOPT_SSLVERSION;
	    if (strEQ(name, "STDERR")) return CURLOPT_STDERR;
	    if (strEQ(name, "TIMECONDITION")) return CURLOPT_TIMECONDITION;
	    if (strEQ(name, "TIMEOUT")) return CURLOPT_TIMEOUT;
	    if (strEQ(name, "TIMEVALUE")) return CURLOPT_TIMEVALUE;
	    if (strEQ(name, "TRANSFERTEXT")) return CURLOPT_TRANSFERTEXT;
	    break;
	case 'U':
	case 'V':
	    if (strEQ(name, "UPLOAD")) return CURLOPT_UPLOAD;
	    if (strEQ(name, "URL")) return CURLOPT_URL;
	    if (strEQ(name, "USERAGENT")) return CURLOPT_USERAGENT;
	    if (strEQ(name, "USERPWD")) return CURLOPT_USERPWD;
	    if (strEQ(name, "VERBOSE")) return CURLOPT_VERBOSE;
	    break;
	case 'W':
	case 'X':
	case 'Y':
	case 'Z':
	    if (strEQ(name, "WRITEFUNCTION")) return CURLOPT_WRITEFUNCTION;
	    if (strEQ(name, "WRITEHEADER")) return CURLOPT_WRITEHEADER;
	    if (strEQ(name, "WRITEINFO")) return CURLOPT_WRITEINFO;
	    break;
	}
    }
    errno = EINVAL;
    return 0;
}


MODULE = Curl::easy		PACKAGE = Curl::easy		

int
constant(name,arg)
    char * name
    int arg


void *
curl_easy_init()
CODE:
    if (errbufvarname) free(errbufvarname);
    errbufvarname = NULL;
    RETVAL = curl_easy_init();
OUTPUT:
    RETVAL


int
curl_easy_setopt(curl, option, value)
void * curl
int option
char * value
CODE:
    if (option < CURLOPTTYPE_OBJECTPOINT) {
	/* This is an option specifying an integer value: */
	long value = (long)SvIV(ST(2));
	RETVAL = curl_easy_setopt(curl, option, value);
    } else if (option == CURLOPT_FILE || option == CURLOPT_INFILE ||
	    option == CURLOPT_WRITEHEADER) {
	/* This is an option specifying a FILE * value: */
	FILE * value = IoIFP(sv_2io(ST(2)));
	RETVAL = curl_easy_setopt(curl, option, value);
    } else if (option == CURLOPT_ERRORBUFFER) {
	SV *sv;
	RETVAL = curl_easy_setopt(curl, option, errbuf);
	if (errbufvarname) free(errbufvarname);
	errbufvarname = strdup(value);
	sv = perl_get_sv(errbufvarname, TRUE | GV_ADDMULTI);
    } else if (option == CURLOPT_WRITEFUNCTION || option ==
	    CURLOPT_READFUNCTION || option == CURLOPT_PROGRESSFUNCTION) {
	/* This is an option specifying a callback function */
	/* not yet implemented */
	RETVAL = -1;
    } else {
	/* default, option specifying a char * value: */
	RETVAL = curl_easy_setopt(curl, option, value);
    }
OUTPUT:
    RETVAL


int
curl_easy_perform(curl)
void * curl 
CODE:
    RETVAL = curl_easy_perform(curl);
    if (RETVAL && errbufvarname) {
	SV *sv = perl_get_sv(errbufvarname, TRUE | GV_ADDMULTI);
	sv_setpv(sv, errbuf);
    }
OUTPUT:
    RETVAL


int
curl_easy_getinfo(curl, option, value)
void * curl
int option
double value
CODE:
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
    if (errbufvarname) free(errbufvarname);
    errbufvarname = NULL;
    RETVAL = 0;
OUTPUT:
    RETVAL

