%{
/*
**  Originally written by Steven M. Bellovin <smb@research.att.com> while
**  at the University of North Carolina at Chapel Hill.  Later tweaked by
**  a couple of people on Usenet.  Completely overhauled by Rich $alz
**  <rsalz@bbn.com> and Jim Berets <jberets@bbn.com> in August, 1990.
**
**  This code has been modified since it was included in curl, to make it
**  thread-safe and to make compilers complain less about it.
**
**  This code is in the public domain and has no copyright.
*/

#include "setup.h"

# ifdef HAVE_ALLOCA_H
#  include <alloca.h>
# endif

# ifdef HAVE_TIME_H
#  include <time.h>
# endif

#ifndef YYDEBUG
  /* to satisfy gcc -Wundef, we set this to 0 */
#define YYDEBUG 0
#endif

/* Since the code of getdate.y is not included in the Emacs executable
   itself, there is no need to #define static in this file.  Even if
   the code were included in the Emacs executable, it probably
   wouldn't do any harm to #undef it here; this will only cause
   problems if we try to write to a static variable, which I don't
   think this code needs to do.  */
#ifdef emacs
# undef static
#endif

#ifdef __APPLE__
#include <sys/types.h>
#include <sys/malloc.h>
#else

#endif
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#if HAVE_STDLIB_H
# include <stdlib.h> /* for `free'; used by Bison 1.27 */
#else

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#endif

#if defined (STDC_HEADERS) || (!defined (isascii) && !defined (HAVE_ISASCII))
# define IN_CTYPE_DOMAIN(c) 1
#else
# define IN_CTYPE_DOMAIN(c) isascii(c)
#endif

#define ISSPACE(c) (IN_CTYPE_DOMAIN (c) && isspace (c))
#define ISALPHA(c) (IN_CTYPE_DOMAIN (c) && isalpha (c))
#define ISUPPER(c) (IN_CTYPE_DOMAIN (c) && isupper (c))
#define ISDIGIT_LOCALE(c) (IN_CTYPE_DOMAIN (c) && isdigit (c))

/* ISDIGIT differs from ISDIGIT_LOCALE, as follows:
   - Its arg may be any int or unsigned int; it need not be an unsigned char.
   - It's guaranteed to evaluate its argument exactly once.
   - It's typically faster.
   Posix 1003.2-1992 section 2.5.2.1 page 50 lines 1556-1558 says that
   only '0' through '9' are digits.  Prefer ISDIGIT to ISDIGIT_LOCALE unless
   it's important to use the locale's definition of `digit' even when the
   host does not conform to Posix.  */
#define ISDIGIT(c) ((unsigned) (c) - '0' <= 9)

#if defined (STDC_HEADERS) || defined (USG)
# include <string.h>
#endif

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

#ifndef YYMAXDEPTH
#define YYMAXDEPTH 0
#endif

#if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 7)
# define __attribute__(x)
#endif

#ifndef ATTRIBUTE_UNUSED
# define ATTRIBUTE_UNUSED __attribute__ ((__unused__))
#endif

/* Some old versions of bison generate parsers that use bcopy.
   That loses on systems that don't provide the function, so we have
   to redefine it here.  */
#if !defined (HAVE_BCOPY) && defined (HAVE_MEMCPY) && !defined (bcopy)
# define bcopy(from, to, len) memcpy ((to), (from), (len))
#endif

/* Remap normal yacc parser interface names (yyparse, yylex, yyerror, etc),
   as well as gratuitiously global symbol names, so we can have multiple
   yacc generated parsers in the same program.  Note that these are only
   the variables produced by yacc.  If other parser generators (bison,
   byacc, etc) produce additional global names that conflict at link time,
   then those parser generators need to be fixed instead of adding those
   names to this list. */

#define yymaxdepth Curl_gd_maxdepth
#define yyparse Curl_gd_parse
#define yylex   Curl_gd_lex
#define yyerror Curl_gd_error
#define yylval  Curl_gd_lval
#define yychar  Curl_gd_char
#define yydebug Curl_gd_debug
#define yypact  Curl_gd_pact
#define yyr1    Curl_gd_r1
#define yyr2    Curl_gd_r2
#define yydef   Curl_gd_def
#define yychk   Curl_gd_chk
#define yypgo   Curl_gd_pgo
#define yyact   Curl_gd_act
#define yyexca  Curl_gd_exca
#define yyerrflag Curl_gd_errflag
#define yynerrs Curl_gd_nerrs
#define yyps    Curl_gd_ps
#define yypv    Curl_gd_pv
#define yys     Curl_gd_s
#define yy_yys  Curl_gd_yys
#define yystate Curl_gd_state
#define yytmp   Curl_gd_tmp
#define yyv     Curl_gd_v
#define yy_yyv  Curl_gd_yyv
#define yyval   Curl_gd_val
#define yylloc  Curl_gd_lloc
#define yyreds  Curl_gd_reds          /* With YYDEBUG defined */
#define yytoks  Curl_gd_toks          /* With YYDEBUG defined */
#define yylhs   Curl_gd_yylhs
#define yylen   Curl_gd_yylen
#define yydefred Curl_gd_yydefred
#define yydgoto Curl_gd_yydgoto
#define yysindex Curl_gd_yysindex
#define yyrindex Curl_gd_yyrindex
#define yygindex Curl_gd_yygindex
#define yytable  Curl_gd_yytable
#define yycheck  Curl_gd_yycheck

#define EPOCH		1970
#define HOUR(x)		((x) * 60)

#define MAX_BUFF_LEN    128   /* size of buffer to read the date into */

/*
**  An entry in the lexical lookup table.
*/
typedef struct _TABLE {
    const char	*name;
    int		type;
    int		value;
} TABLE;


/*
**  Meridian:  am, pm, or 24-hour style.
*/
typedef enum _MERIDIAN {
    MERam, MERpm, MER24
} MERIDIAN;

/* parse results and input string */
typedef struct _CURL_CONTEXT {
    const char	*yyInput;
    int		yyDayOrdinal;
    int		yyDayNumber;
    int		yyHaveDate;
    int		yyHaveDay;
    int		yyHaveRel;
    int		yyHaveTime;
    int		yyHaveZone;
    int		yyTimezone;
    int		yyDay;
    int		yyHour;
    int		yyMinutes;
    int		yyMonth;
    int		yySeconds;
    int		yyYear;
    MERIDIAN	yyMeridian;
    int		yyRelDay;
    int		yyRelHour;
    int		yyRelMinutes;
    int		yyRelMonth;
    int		yyRelSeconds;
    int		yyRelYear;
} CURL_CONTEXT;

/* enable use of extra argument to yyparse and yylex which can be used to pass
**  in a user defined value (CURL_CONTEXT struct in our case)
*/
#define YYPARSE_PARAM cookie
#define YYLEX_PARAM cookie
#define context ((CURL_CONTEXT *) cookie)
%}

/* This grammar has 13 shift/reduce conflicts. */
%expect 13

/* turn global variables into locals, additionally enable extra arguments
** for yylex (pointer to yylval and user defined value)
*/
%pure_parser

%union {
    int			Number;
    enum _MERIDIAN	Meridian;
}

%{
static int yylex (YYSTYPE *yylval, void *cookie);
static int yyerror (const char *s);
%}

%token	tAGO tDAY tDAY_UNIT tDAYZONE tDST tHOUR_UNIT tID
%token	tMERIDIAN tMINUTE_UNIT tMONTH tMONTH_UNIT
%token	tSEC_UNIT tSNUMBER tUNUMBER tYEAR_UNIT tZONE

%type	<Number>	tDAY tDAY_UNIT tDAYZONE tHOUR_UNIT tMINUTE_UNIT
%type	<Number>	tMONTH tMONTH_UNIT
%type	<Number>	tSEC_UNIT tSNUMBER tUNUMBER tYEAR_UNIT tZONE
%type	<Meridian>	tMERIDIAN o_merid

%%

spec	: /* NULL */
	| spec item
	;

item	: time {
	    context->yyHaveTime++;
	}
	| zone {
	    context->yyHaveZone++;
	}
	| date {
	    context->yyHaveDate++;
	}
	| day {
	    context->yyHaveDay++;
	}
	| rel {
	    context->yyHaveRel++;
	}
	| number
	;

time	: tUNUMBER tMERIDIAN {
	    context->yyHour = $1;
	    context->yyMinutes = 0;
	    context->yySeconds = 0;
	    context->yyMeridian = $2;
	}
	| tUNUMBER ':' tUNUMBER o_merid {
	    context->yyHour = $1;
	    context->yyMinutes = $3;
	    context->yySeconds = 0;
	    context->yyMeridian = $4;
	}
	| tUNUMBER ':' tUNUMBER tSNUMBER {
	    context->yyHour = $1;
	    context->yyMinutes = $3;
	    context->yyMeridian = MER24;
	    context->yyHaveZone++;
	    context->yyTimezone = ($4 < 0
				   ? -$4 % 100 + (-$4 / 100) * 60
				   : - ($4 % 100 + ($4 / 100) * 60));
	}
	| tUNUMBER ':' tUNUMBER ':' tUNUMBER o_merid {
	    context->yyHour = $1;
	    context->yyMinutes = $3;
	    context->yySeconds = $5;
	    context->yyMeridian = $6;
	}
	| tUNUMBER ':' tUNUMBER ':' tUNUMBER tSNUMBER {
	    context->yyHour = $1;
	    context->yyMinutes = $3;
	    context->yySeconds = $5;
	    context->yyMeridian = MER24;
	    context->yyHaveZone++;
	    context->yyTimezone = ($6 < 0
				   ? -$6 % 100 + (-$6 / 100) * 60
				   : - ($6 % 100 + ($6 / 100) * 60));
	}
	;

zone	: tZONE {
	    context->yyTimezone = $1;
	}
	| tDAYZONE {
	    context->yyTimezone = $1 - 60;
	}
	|
	  tZONE tDST {
	    context->yyTimezone = $1 - 60;
	}
	;

day	: tDAY {
	    context->yyDayOrdinal = 1;
	    context->yyDayNumber = $1;
	}
	| tDAY ',' {
	    context->yyDayOrdinal = 1;
	    context->yyDayNumber = $1;
	}
	| tUNUMBER tDAY {
	    context->yyDayOrdinal = $1;
	    context->yyDayNumber = $2;
	}
	;

date	: tUNUMBER '/' tUNUMBER {
	    context->yyMonth = $1;
	    context->yyDay = $3;
	}
	| tUNUMBER '/' tUNUMBER '/' tUNUMBER {
	  /* Interpret as YYYY/MM/DD if $1 >= 1000, otherwise as MM/DD/YY.
	     The goal in recognizing YYYY/MM/DD is solely to support legacy
	     machine-generated dates like those in an RCS log listing.  If
	     you want portability, use the ISO 8601 format.  */
	  if ($1 >= 1000)
	    {
	      context->yyYear = $1;
	      context->yyMonth = $3;
	      context->yyDay = $5;
	    }
	  else
	    {
	      context->yyMonth = $1;
	      context->yyDay = $3;
	      context->yyYear = $5;
	    }
	}
	| tUNUMBER tSNUMBER tSNUMBER {
	    /* ISO 8601 format.  yyyy-mm-dd.  */
	    context->yyYear = $1;
	    context->yyMonth = -$2;
	    context->yyDay = -$3;
	}
	| tUNUMBER tMONTH tSNUMBER {
	    /* e.g. 17-JUN-1992.  */
	    context->yyDay = $1;
	    context->yyMonth = $2;
	    context->yyYear = -$3;
	}
	| tMONTH tUNUMBER {
	    context->yyMonth = $1;
	    context->yyDay = $2;
	}
	| tMONTH tUNUMBER ',' tUNUMBER {
	    context->yyMonth = $1;
	    context->yyDay = $2;
	    context->yyYear = $4;
	}
	| tUNUMBER tMONTH {
	    context->yyMonth = $2;
	    context->yyDay = $1;
	}
	| tUNUMBER tMONTH tUNUMBER {
	    context->yyMonth = $2;
	    context->yyDay = $1;
	    context->yyYear = $3;
	}
	;

rel	: relunit tAGO {
	    context->yyRelSeconds = -context->yyRelSeconds;
	    context->yyRelMinutes = -context->yyRelMinutes;
	    context->yyRelHour = -context->yyRelHour;
	    context->yyRelDay = -context->yyRelDay;
	    context->yyRelMonth = -context->yyRelMonth;
	    context->yyRelYear = -context->yyRelYear;
	}
	| relunit
	;

relunit	: tUNUMBER tYEAR_UNIT {
	    context->yyRelYear += $1 * $2;
	}
	| tSNUMBER tYEAR_UNIT {
	    context->yyRelYear += $1 * $2;
	}
	| tYEAR_UNIT {
	    context->yyRelYear += $1;
	}
	| tUNUMBER tMONTH_UNIT {
	    context->yyRelMonth += $1 * $2;
	}
	| tSNUMBER tMONTH_UNIT {
	    context->yyRelMonth += $1 * $2;
	}
	| tMONTH_UNIT {
	    context->yyRelMonth += $1;
	}
	| tUNUMBER tDAY_UNIT {
	    context->yyRelDay += $1 * $2;
	}
	| tSNUMBER tDAY_UNIT {
	    context->yyRelDay += $1 * $2;
	}
	| tDAY_UNIT {
	    context->yyRelDay += $1;
	}
	| tUNUMBER tHOUR_UNIT {
	    context->yyRelHour += $1 * $2;
	}
	| tSNUMBER tHOUR_UNIT {
	    context->yyRelHour += $1 * $2;
	}
	| tHOUR_UNIT {
	    context->yyRelHour += $1;
	}
	| tUNUMBER tMINUTE_UNIT {
	    context->yyRelMinutes += $1 * $2;
	}
	| tSNUMBER tMINUTE_UNIT {
	    context->yyRelMinutes += $1 * $2;
	}
	| tMINUTE_UNIT {
	    context->yyRelMinutes += $1;
	}
	| tUNUMBER tSEC_UNIT {
	    context->yyRelSeconds += $1 * $2;
	}
	| tSNUMBER tSEC_UNIT {
	    context->yyRelSeconds += $1 * $2;
	}
	| tSEC_UNIT {
	    context->yyRelSeconds += $1;
	}
	;

number	: tUNUMBER
          {
	    if (context->yyHaveTime && context->yyHaveDate &&
		!context->yyHaveRel)
	      context->yyYear = $1;
	    else
	      {
		if ($1>10000)
		  {
		    context->yyHaveDate++;
		    context->yyDay= ($1)%100;
		    context->yyMonth= ($1/100)%100;
		    context->yyYear = $1/10000;
		  }
		else
		  {
		    context->yyHaveTime++;
		    if ($1 < 100)
		      {
			context->yyHour = $1;
			context->yyMinutes = 0;
		      }
		    else
		      {
		    	context->yyHour = $1 / 100;
		    	context->yyMinutes = $1 % 100;
		      }
		    context->yySeconds = 0;
		    context->yyMeridian = MER24;
		  }
	      }
	  }
	;

o_merid	: /* NULL */
	  {
	    $$ = MER24;
	  }
	| tMERIDIAN
	  {
	    $$ = $1;
	  }
	;

%%

/* Include this file down here because bison inserts code above which
   may define-away `const'.  We want the prototype for get_date to have
   the same signature as the function definition does. */
#include "getdate.h"

#ifndef WIN32 /* the windows dudes don't need these, does anyone really? */
extern struct tm	*gmtime (const time_t *);
extern struct tm	*localtime (const time_t *);
extern time_t		mktime (struct tm *);
#endif

/* Month and day table. */
static TABLE const MonthDayTable[] = {
    { "january",	tMONTH,  1 },
    { "february",	tMONTH,  2 },
    { "march",		tMONTH,  3 },
    { "april",		tMONTH,  4 },
    { "may",		tMONTH,  5 },
    { "june",		tMONTH,  6 },
    { "july",		tMONTH,  7 },
    { "august",		tMONTH,  8 },
    { "september",	tMONTH,  9 },
    { "sept",		tMONTH,  9 },
    { "october",	tMONTH, 10 },
    { "november",	tMONTH, 11 },
    { "december",	tMONTH, 12 },
    { "sunday",		tDAY, 0 },
    { "monday",		tDAY, 1 },
    { "tuesday",	tDAY, 2 },
    { "tues",		tDAY, 2 },
    { "wednesday",	tDAY, 3 },
    { "wednes",		tDAY, 3 },
    { "thursday",	tDAY, 4 },
    { "thur",		tDAY, 4 },
    { "thurs",		tDAY, 4 },
    { "friday",		tDAY, 5 },
    { "saturday",	tDAY, 6 },
    { NULL, 0, 0 }
};

/* Time units table. */
static TABLE const UnitsTable[] = {
    { "year",		tYEAR_UNIT,	1 },
    { "month",		tMONTH_UNIT,	1 },
    { "fortnight",	tDAY_UNIT,	14 },
    { "week",		tDAY_UNIT,	7 },
    { "day",		tDAY_UNIT,	1 },
    { "hour",		tHOUR_UNIT,	1 },
    { "minute",		tMINUTE_UNIT,	1 },
    { "min",		tMINUTE_UNIT,	1 },
    { "second",		tSEC_UNIT,	1 },
    { "sec",		tSEC_UNIT,	1 },
    { NULL, 0, 0 }
};

/* Assorted relative-time words. */
static TABLE const OtherTable[] = {
    { "tomorrow",	tMINUTE_UNIT,	1 * 24 * 60 },
    { "yesterday",	tMINUTE_UNIT,	-1 * 24 * 60 },
    { "today",		tMINUTE_UNIT,	0 },
    { "now",		tMINUTE_UNIT,	0 },
    { "last",		tUNUMBER,	-1 },
    { "this",		tMINUTE_UNIT,	0 },
    { "next",		tUNUMBER,	1 },
    { "first",		tUNUMBER,	1 },
/*  { "second",		tUNUMBER,	2 }, */
    { "third",		tUNUMBER,	3 },
    { "fourth",		tUNUMBER,	4 },
    { "fifth",		tUNUMBER,	5 },
    { "sixth",		tUNUMBER,	6 },
    { "seventh",	tUNUMBER,	7 },
    { "eighth",		tUNUMBER,	8 },
    { "ninth",		tUNUMBER,	9 },
    { "tenth",		tUNUMBER,	10 },
    { "eleventh",	tUNUMBER,	11 },
    { "twelfth",	tUNUMBER,	12 },
    { "ago",		tAGO,	1 },
    { NULL, 0, 0 }
};

/* The timezone table. */
static TABLE const TimezoneTable[] = {
    { "gmt",	tZONE,     HOUR ( 0) },	/* Greenwich Mean */
    { "ut",	tZONE,     HOUR ( 0) },	/* Universal (Coordinated) */
    { "utc",	tZONE,     HOUR ( 0) },
    { "wet",	tZONE,     HOUR ( 0) },	/* Western European */
    { "bst",	tDAYZONE,  HOUR ( 0) },	/* British Summer */
    { "wat",	tZONE,     HOUR ( 1) },	/* West Africa */
    { "at",	tZONE,     HOUR ( 2) },	/* Azores */
#if	0
    /* For completeness.  BST is also British Summer, and GST is
     * also Guam Standard. */
    { "bst",	tZONE,     HOUR ( 3) },	/* Brazil Standard */
    { "gst",	tZONE,     HOUR ( 3) },	/* Greenland Standard */
#endif
#if 0
    { "nft",	tZONE,     HOUR (3.5) },	/* Newfoundland */
    { "nst",	tZONE,     HOUR (3.5) },	/* Newfoundland Standard */
    { "ndt",	tDAYZONE,  HOUR (3.5) },	/* Newfoundland Daylight */
#endif
    { "ast",	tZONE,     HOUR ( 4) },	/* Atlantic Standard */
    { "adt",	tDAYZONE,  HOUR ( 4) },	/* Atlantic Daylight */
    { "est",	tZONE,     HOUR ( 5) },	/* Eastern Standard */
    { "edt",	tDAYZONE,  HOUR ( 5) },	/* Eastern Daylight */
    { "cst",	tZONE,     HOUR ( 6) },	/* Central Standard */
    { "cdt",	tDAYZONE,  HOUR ( 6) },	/* Central Daylight */
    { "mst",	tZONE,     HOUR ( 7) },	/* Mountain Standard */
    { "mdt",	tDAYZONE,  HOUR ( 7) },	/* Mountain Daylight */
    { "pst",	tZONE,     HOUR ( 8) },	/* Pacific Standard */
    { "pdt",	tDAYZONE,  HOUR ( 8) },	/* Pacific Daylight */
    { "yst",	tZONE,     HOUR ( 9) },	/* Yukon Standard */
    { "ydt",	tDAYZONE,  HOUR ( 9) },	/* Yukon Daylight */
    { "hst",	tZONE,     HOUR (10) },	/* Hawaii Standard */
    { "hdt",	tDAYZONE,  HOUR (10) },	/* Hawaii Daylight */
    { "cat",	tZONE,     HOUR (10) },	/* Central Alaska */
    { "ahst",	tZONE,     HOUR (10) },	/* Alaska-Hawaii Standard */
    { "nt",	tZONE,     HOUR (11) },	/* Nome */
    { "idlw",	tZONE,     HOUR (12) },	/* International Date Line West */
    { "cet",	tZONE,     -HOUR (1) },	/* Central European */
    { "met",	tZONE,     -HOUR (1) },	/* Middle European */
    { "mewt",	tZONE,     -HOUR (1) },	/* Middle European Winter */
    { "mest",	tDAYZONE,  -HOUR (1) },	/* Middle European Summer */
    { "mesz",	tDAYZONE,  -HOUR (1) },	/* Middle European Summer */
    { "swt",	tZONE,     -HOUR (1) },	/* Swedish Winter */
    { "sst",	tDAYZONE,  -HOUR (1) },	/* Swedish Summer */
    { "fwt",	tZONE,     -HOUR (1) },	/* French Winter */
    { "fst",	tDAYZONE,  -HOUR (1) },	/* French Summer */
    { "eet",	tZONE,     -HOUR (2) },	/* Eastern Europe, USSR Zone 1 */
    { "bt",	tZONE,     -HOUR (3) },	/* Baghdad, USSR Zone 2 */
#if 0
    { "it",	tZONE,     -HOUR (3.5) },/* Iran */
#endif
    { "zp4",	tZONE,     -HOUR (4) },	/* USSR Zone 3 */
    { "zp5",	tZONE,     -HOUR (5) },	/* USSR Zone 4 */
#if 0
    { "ist",	tZONE,     -HOUR (5.5) },/* Indian Standard */
#endif
    { "zp6",	tZONE,     -HOUR (6) },	/* USSR Zone 5 */
#if	0
    /* For completeness.  NST is also Newfoundland Standard, and SST is
     * also Swedish Summer. */
    { "nst",	tZONE,     -HOUR (6.5) },/* North Sumatra */
    { "sst",	tZONE,     -HOUR (7) },	/* South Sumatra, USSR Zone 6 */
#endif	/* 0 */
    { "wast",	tZONE,     -HOUR (7) },	/* West Australian Standard */
    { "wadt",	tDAYZONE,  -HOUR (7) },	/* West Australian Daylight */
#if 0
    { "jt",	tZONE,     -HOUR (7.5) },/* Java (3pm in Cronusland!) */
#endif
    { "cct",	tZONE,     -HOUR (8) },	/* China Coast, USSR Zone 7 */
    { "jst",	tZONE,     -HOUR (9) },	/* Japan Standard, USSR Zone 8 */
#if 0
    { "cast",	tZONE,     -HOUR (9.5) },/* Central Australian Standard */
    { "cadt",	tDAYZONE,  -HOUR (9.5) },/* Central Australian Daylight */
#endif
    { "east",	tZONE,     -HOUR (10) },	/* Eastern Australian Standard */
    { "eadt",	tDAYZONE,  -HOUR (10) },	/* Eastern Australian Daylight */
    { "gst",	tZONE,     -HOUR (10) },	/* Guam Standard, USSR Zone 9 */
    { "nzt",	tZONE,     -HOUR (12) },	/* New Zealand */
    { "nzst",	tZONE,     -HOUR (12) },	/* New Zealand Standard */
    { "nzdt",	tDAYZONE,  -HOUR (12) },	/* New Zealand Daylight */
    { "idle",	tZONE,     -HOUR (12) },	/* International Date Line East */
    {  NULL, 0, 0  }
};

/* Military timezone table. */
static TABLE const MilitaryTable[] = {
    { "a",	tZONE,	HOUR (  1) },
    { "b",	tZONE,	HOUR (  2) },
    { "c",	tZONE,	HOUR (  3) },
    { "d",	tZONE,	HOUR (  4) },
    { "e",	tZONE,	HOUR (  5) },
    { "f",	tZONE,	HOUR (  6) },
    { "g",	tZONE,	HOUR (  7) },
    { "h",	tZONE,	HOUR (  8) },
    { "i",	tZONE,	HOUR (  9) },
    { "k",	tZONE,	HOUR ( 10) },
    { "l",	tZONE,	HOUR ( 11) },
    { "m",	tZONE,	HOUR ( 12) },
    { "n",	tZONE,	HOUR (- 1) },
    { "o",	tZONE,	HOUR (- 2) },
    { "p",	tZONE,	HOUR (- 3) },
    { "q",	tZONE,	HOUR (- 4) },
    { "r",	tZONE,	HOUR (- 5) },
    { "s",	tZONE,	HOUR (- 6) },
    { "t",	tZONE,	HOUR (- 7) },
    { "u",	tZONE,	HOUR (- 8) },
    { "v",	tZONE,	HOUR (- 9) },
    { "w",	tZONE,	HOUR (-10) },
    { "x",	tZONE,	HOUR (-11) },
    { "y",	tZONE,	HOUR (-12) },
    { "z",	tZONE,	HOUR (  0) },
    { NULL, 0, 0 }
};




/* ARGSUSED */
static int
yyerror (const char *s ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
ToHour (int Hours, MERIDIAN Meridian)
{
  switch (Meridian)
    {
    case MER24:
      if (Hours < 0 || Hours > 23)
	return -1;
      return Hours;
    case MERam:
      if (Hours < 1 || Hours > 12)
	return -1;
      if (Hours == 12)
	Hours = 0;
      return Hours;
    case MERpm:
      if (Hours < 1 || Hours > 12)
	return -1;
      if (Hours == 12)
	Hours = 0;
      return Hours + 12;
    default:
      abort ();
    }
  /* NOTREACHED */
}

static int
ToYear (int Year)
{
  if (Year < 0)
    Year = -Year;

  /* XPG4 suggests that years 00-68 map to 2000-2068, and
     years 69-99 map to 1969-1999.  */
  if (Year < 69)
    Year += 2000;
  else if (Year < 100)
    Year += 1900;

  return Year;
}

static int
LookupWord (YYSTYPE *yylval, char *buff)
{
  register char *p;
  register char *q;
  register const TABLE *tp;
  int i;
  int abbrev;

  /* Make it lowercase. */
  for (p = buff; *p; p++)
    if (ISUPPER ((unsigned char) *p))
      *p = tolower (*p);

  if (strcmp (buff, "am") == 0 || strcmp (buff, "a.m.") == 0)
    {
      yylval->Meridian = MERam;
      return tMERIDIAN;
    }
  if (strcmp (buff, "pm") == 0 || strcmp (buff, "p.m.") == 0)
    {
      yylval->Meridian = MERpm;
      return tMERIDIAN;
    }

  /* See if we have an abbreviation for a month. */
  if (strlen (buff) == 3)
    abbrev = 1;
  else if (strlen (buff) == 4 && buff[3] == '.')
    {
      abbrev = 1;
      buff[3] = '\0';
    }
  else
    abbrev = 0;

  for (tp = MonthDayTable; tp->name; tp++)
    {
      if (abbrev)
	{
	  if (strncmp (buff, tp->name, 3) == 0)
	    {
	      yylval->Number = tp->value;
	      return tp->type;
	    }
	}
      else if (strcmp (buff, tp->name) == 0)
	{
	  yylval->Number = tp->value;
	  return tp->type;
	}
    }

  for (tp = TimezoneTable; tp->name; tp++)
    if (strcmp (buff, tp->name) == 0)
      {
	yylval->Number = tp->value;
	return tp->type;
      }

  if (strcmp (buff, "dst") == 0)
    return tDST;

  for (tp = UnitsTable; tp->name; tp++)
    if (strcmp (buff, tp->name) == 0)
      {
	yylval->Number = tp->value;
	return tp->type;
      }

  /* Strip off any plural and try the units table again. */
  i = strlen (buff) - 1;
  if (buff[i] == 's')
    {
      buff[i] = '\0';
      for (tp = UnitsTable; tp->name; tp++)
	if (strcmp (buff, tp->name) == 0)
	  {
	    yylval->Number = tp->value;
	    return tp->type;
	  }
      buff[i] = 's';		/* Put back for "this" in OtherTable. */
    }

  for (tp = OtherTable; tp->name; tp++)
    if (strcmp (buff, tp->name) == 0)
      {
	yylval->Number = tp->value;
	return tp->type;
      }

  /* Military timezones. */
  if (buff[1] == '\0' && ISALPHA ((unsigned char) *buff))
    {
      for (tp = MilitaryTable; tp->name; tp++)
	if (strcmp (buff, tp->name) == 0)
	  {
	    yylval->Number = tp->value;
	    return tp->type;
	  }
    }

  /* Drop out any periods and try the timezone table again. */
  for (i = 0, p = q = buff; *q; q++)
    if (*q != '.')
      *p++ = *q;
    else
      i++;
  *p = '\0';
  if (i)
    for (tp = TimezoneTable; tp->name; tp++)
      if (strcmp (buff, tp->name) == 0)
	{
	  yylval->Number = tp->value;
	  return tp->type;
	}

  return tID;
}

static int
yylex (YYSTYPE *yylval, void *cookie)
{
  register unsigned char c;
  register char *p;
  char buff[20];
  int Count;
  int sign;

  for (;;)
    {
      while (ISSPACE ((unsigned char) *context->yyInput))
	context->yyInput++;

      if (ISDIGIT (c = *context->yyInput) || c == '-' || c == '+')
	{
	  if (c == '-' || c == '+')
	    {
	      sign = c == '-' ? -1 : 1;
	      if (!ISDIGIT (*++context->yyInput))
		/* skip the '-' sign */
		continue;
	    }
	  else
	    sign = 0;
	  for (yylval->Number = 0; ISDIGIT (c = *context->yyInput++);)
	    yylval->Number = 10 * yylval->Number + c - '0';
	  context->yyInput--;
	  if (sign < 0)
	    yylval->Number = -yylval->Number;
	  return sign ? tSNUMBER : tUNUMBER;
	}
      if (ISALPHA (c))
	{
	  for (p = buff; (c = *context->yyInput++, ISALPHA (c)) || c == '.';)
	    if (p < &buff[sizeof buff - 1])
	      *p++ = c;
	  *p = '\0';
	  context->yyInput--;
	  return LookupWord (yylval, buff);
	}
      if (c != '(')
	return *context->yyInput++;
      Count = 0;
      do
	{
	  c = *context->yyInput++;
	  if (c == '\0')
	    return c;
	  if (c == '(')
	    Count++;
	  else if (c == ')')
	    Count--;
	}
      while (Count > 0);
    }
}

#define TM_YEAR_ORIGIN 1900

/* Yield A - B, measured in seconds.  */
static long
difftm (struct tm *a, struct tm *b)
{
  int ay = a->tm_year + (TM_YEAR_ORIGIN - 1);
  int by = b->tm_year + (TM_YEAR_ORIGIN - 1);
  long days = (
  /* difference in day of year */
		a->tm_yday - b->tm_yday
  /* + intervening leap days */
		+ ((ay >> 2) - (by >> 2))
		- (ay / 100 - by / 100)
		+ ((ay / 100 >> 2) - (by / 100 >> 2))
  /* + difference in years * 365 */
		+ (long) (ay - by) * 365
  );
  return (60 * (60 * (24 * days + (a->tm_hour - b->tm_hour))
		+ (a->tm_min - b->tm_min))
	  + (a->tm_sec - b->tm_sec));
}

time_t
curl_getdate (const char *p, const time_t *now)
{
  struct tm tm, tm0, *tmp;
  time_t Start;
  CURL_CONTEXT cookie;
#ifdef HAVE_LOCALTIME_R
  struct tm keeptime;
#endif
  cookie.yyInput = p;
  Start = now ? *now : time ((time_t *) NULL);
#ifdef HAVE_LOCALTIME_R
  tmp = (struct tm *)localtime_r(&Start, &keeptime);
#else
  tmp = localtime (&Start);
#endif
  if (!tmp)
    return -1;
  cookie.yyYear = tmp->tm_year + TM_YEAR_ORIGIN;
  cookie.yyMonth = tmp->tm_mon + 1;
  cookie.yyDay = tmp->tm_mday;
  cookie.yyHour = tmp->tm_hour;
  cookie.yyMinutes = tmp->tm_min;
  cookie.yySeconds = tmp->tm_sec;
  tm.tm_isdst = tmp->tm_isdst;
  cookie.yyMeridian = MER24;
  cookie.yyRelSeconds = 0;
  cookie.yyRelMinutes = 0;
  cookie.yyRelHour = 0;
  cookie.yyRelDay = 0;
  cookie.yyRelMonth = 0;
  cookie.yyRelYear = 0;
  cookie.yyHaveDate = 0;
  cookie.yyHaveDay = 0;
  cookie.yyHaveRel = 0;
  cookie.yyHaveTime = 0;
  cookie.yyHaveZone = 0;

  if (yyparse (&cookie)
      || cookie.yyHaveTime > 1 || cookie.yyHaveZone > 1 ||
      cookie.yyHaveDate > 1 || cookie.yyHaveDay > 1)
    return -1;

  tm.tm_year = ToYear (cookie.yyYear) - TM_YEAR_ORIGIN + cookie.yyRelYear;
  tm.tm_mon = cookie.yyMonth - 1 + cookie.yyRelMonth;
  tm.tm_mday = cookie.yyDay + cookie.yyRelDay;
  if (cookie.yyHaveTime ||
      (cookie.yyHaveRel && !cookie.yyHaveDate && !cookie.yyHaveDay))
    {
      tm.tm_hour = ToHour (cookie.yyHour, cookie.yyMeridian);
      if (tm.tm_hour < 0)
	return -1;
      tm.tm_min = cookie.yyMinutes;
      tm.tm_sec = cookie.yySeconds;
    }
  else
    {
      tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
    }
  tm.tm_hour += cookie.yyRelHour;
  tm.tm_min += cookie.yyRelMinutes;
  tm.tm_sec += cookie.yyRelSeconds;

  /* Let mktime deduce tm_isdst if we have an absolute timestamp,
     or if the relative timestamp mentions days, months, or years.  */
  if (cookie.yyHaveDate | cookie.yyHaveDay | cookie.yyHaveTime |
      cookie.yyRelDay | cookie.yyRelMonth | cookie.yyRelYear)
    tm.tm_isdst = -1;

  tm0 = tm;

  Start = mktime (&tm);

  if (Start == (time_t) -1)
    {

      /* Guard against falsely reporting errors near the time_t boundaries
         when parsing times in other time zones.  For example, if the min
         time_t value is 1970-01-01 00:00:00 UTC and we are 8 hours ahead
         of UTC, then the min localtime value is 1970-01-01 08:00:00; if
         we apply mktime to 1970-01-01 00:00:00 we will get an error, so
         we apply mktime to 1970-01-02 08:00:00 instead and adjust the time
         zone by 24 hours to compensate.  This algorithm assumes that
         there is no DST transition within a day of the time_t boundaries.  */
      if (cookie.yyHaveZone)
	{
	  tm = tm0;
	  if (tm.tm_year <= EPOCH - TM_YEAR_ORIGIN)
	    {
	      tm.tm_mday++;
	      cookie.yyTimezone -= 24 * 60;
	    }
	  else
	    {
	      tm.tm_mday--;
	      cookie.yyTimezone += 24 * 60;
	    }
	  Start = mktime (&tm);
	}

      if (Start == (time_t) -1)
	return Start;
    }

  if (cookie.yyHaveDay && !cookie.yyHaveDate)
    {
      tm.tm_mday += ((cookie.yyDayNumber - tm.tm_wday + 7) % 7
		     + 7 * (cookie.yyDayOrdinal - (0 < cookie.yyDayOrdinal)));
      Start = mktime (&tm);
      if (Start == (time_t) -1)
	return Start;
    }

  if (cookie.yyHaveZone)
    {
      long delta;
      struct tm *gmt;
#ifdef HAVE_GMTIME_R
      /* thread-safe version */
      struct tm keeptime2;
      gmt = (struct tm *)gmtime_r(&Start, &keeptime2);
#else
      gmt = gmtime(&Start);
#endif
      if (!gmt)
	return -1;
      delta = cookie.yyTimezone * 60L + difftm (&tm, gmt);
      if ((Start + delta < Start) != (delta < 0))
	return -1;		/* time_t overflow */
      Start += delta;
    }

  return Start;
}

#if	defined (TEST)

/* ARGSUSED */
int
main (int ac, char *av[])
{
  char buff[MAX_BUFF_LEN + 1];
  time_t d;

  (void) printf ("Enter date, or blank line to exit.\n\t> ");
  (void) fflush (stdout);

  buff[MAX_BUFF_LEN] = 0;
  while (fgets (buff, MAX_BUFF_LEN, stdin) && buff[0])
    {
      d = curl_getdate (buff, (time_t *) NULL);
      if (d == -1)
	(void) printf ("Bad format - couldn't convert.\n");
      else
	(void) printf ("%s", ctime (&d));
      (void) printf ("\t> ");
      (void) fflush (stdout);
    }
  exit (0);
  /* NOTREACHED */
}
#endif /* defined (TEST) */
