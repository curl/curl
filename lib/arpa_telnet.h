#ifndef __ARPA_TELNET_H
#define __ARPA_TELNET_H
/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#ifndef CURL_DISABLE_TELNET
/*
 * Telnet option defines. Add more here if in need.
 */
#define TELOPT_BINARY   0  /* binary 8bit data */
#define TELOPT_SGA      3  /* Supress Go Ahead */
#define TELOPT_EXOPL  255  /* EXtended OPtions List */
#define TELOPT_TTYPE   24  /* Terminal TYPE */
#define TELOPT_XDISPLOC 35 /* X DISPlay LOCation */

#define TELOPT_NEW_ENVIRON 39  /* NEW ENVIRONment variables */
#define NEW_ENV_VAR   0
#define NEW_ENV_VALUE 1

/*
 * The telnet options represented as strings
 */
static const char *telnetoptions[]=
{
  "BINARY",      "ECHO",           "RCP",           "SUPPRESS GO AHEAD",
  "NAME",        "STATUS",         "TIMING MARK",   "RCTE",
  "NAOL",        "NAOP",           "NAOCRD",        "NAOHTS",
  "NAOHTD",      "NAOFFD",         "NAOVTS",        "NAOVTD",
  "NAOLFD",      "EXTEND ASCII",   "LOGOUT",        "BYTE MACRO",
  "DE TERMINAL", "SUPDUP",         "SUPDUP OUTPUT", "SEND LOCATION",
  "TERM TYPE",   "END OF RECORD",  "TACACS UID",    "OUTPUT MARKING",
  "TTYLOC",      "3270 REGIME",    "X3 PAD",        "NAWS",
  "TERM SPEED",  "LFLOW",          "LINEMODE",      "XDISPLOC",
  "OLD-ENVIRON", "AUTHENTICATION", "ENCRYPT",       "NEW-ENVIRON"
};

#define TELOPT_MAXIMUM TELOPT_NEW_ENVIRON

#define TELOPT_OK(x) ((x) <= TELOPT_MAXIMUM)
#define TELOPT(x)    telnetoptions[x]

#define NTELOPTS 40 

/*
 * First some defines
 */
#define xEOF 236 /* End Of File */ 
#define SE   240 /* Sub negotiation End */
#define NOP  241 /* No OPeration */
#define DM   242 /* Data Mark */
#define GA   249 /* Go Ahead, reverse the line */
#define SB   250 /* SuBnegotiation */
#define WILL 251 /* Our side WILL use this option */
#define WONT 252 /* Our side WON'T use this option */
#define DO   253 /* DO use this option! */
#define DONT 254 /* DON'T use this option! */
#define IAC  255 /* Interpret As Command */

/*
 * Then those numbers represented as strings:
 */
static const char *telnetcmds[]=
{
  "EOF",  "SUSP",  "ABORT", "EOR",  "SE",
  "NOP",  "DMARK", "BRK",   "IP",   "AO",
  "AYT",  "EC",    "EL",    "GA",   "SB",
  "WILL", "WONT",  "DO",    "DONT", "IAC"
};

#define TELCMD_MINIMUM xEOF /* the first one */
#define TELCMD_MAXIMUM  IAC  /* surprise, 255 is the last one! ;-) */

#define TELQUAL_IS   0
#define TELQUAL_SEND 1
#define TELQUAL_INFO 2
#define TELQUAL_NAME 3

#define TELCMD_OK(x) ( ((unsigned int)(x) >= TELCMD_MINIMUM) && \
                       ((unsigned int)(x) <= TELCMD_MAXIMUM) )
#define TELCMD(x)    telnetcmds[(x)-TELCMD_MINIMUM]
#endif
#endif
