#ifndef HEADER_FETCH_ARPA_TELNET_H
#define HEADER_FETCH_ARPA_TELNET_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#ifndef FETCH_DISABLE_TELNET
/*
 * Telnet option defines. Add more here if in need.
 */
#define FETCH_TELOPT_BINARY 0    /* binary 8bit data */
#define FETCH_TELOPT_ECHO 1      /* just echo! */
#define FETCH_TELOPT_SGA 3       /* Suppress Go Ahead */
#define FETCH_TELOPT_EXOPL 255   /* EXtended OPtions List */
#define FETCH_TELOPT_TTYPE 24    /* Terminal TYPE */
#define FETCH_TELOPT_NAWS 31     /* Negotiate About Window Size */
#define FETCH_TELOPT_XDISPLOC 35 /* X DISPlay LOCation */

#define FETCH_TELOPT_NEW_ENVIRON 39 /* NEW ENVIRONment variables */
#define FETCH_NEW_ENV_VAR 0
#define FETCH_NEW_ENV_VALUE 1

#ifndef FETCH_DISABLE_VERBOSE_STRINGS
/*
 * The telnet options represented as strings
 */
static const char *const telnetoptions[] =
    {
        "BINARY", "ECHO", "RCP", "SUPPRESS GO AHEAD",
        "NAME", "STATUS", "TIMING MARK", "RCTE",
        "NAOL", "NAOP", "NAOCRD", "NAOHTS",
        "NAOHTD", "NAOFFD", "NAOVTS", "NAOVTD",
        "NAOLFD", "EXTEND ASCII", "LOGOUT", "BYTE MACRO",
        "DE TERMINAL", "SUPDUP", "SUPDUP OUTPUT", "SEND LOCATION",
        "TERM TYPE", "END OF RECORD", "TACACS UID", "OUTPUT MARKING",
        "TTYLOC", "3270 REGIME", "X3 PAD", "NAWS",
        "TERM SPEED", "LFLOW", "LINEMODE", "XDISPLOC",
        "OLD-ENVIRON", "AUTHENTICATION", "ENCRYPT", "NEW-ENVIRON"};
#define FETCH_TELOPT(x) telnetoptions[x]
#else
#define FETCH_TELOPT(x) ""
#endif

#define FETCH_TELOPT_MAXIMUM FETCH_TELOPT_NEW_ENVIRON

#define FETCH_TELOPT_OK(x) ((x) <= FETCH_TELOPT_MAXIMUM)

#define FETCH_NTELOPTS 40

/*
 * First some defines
 */
#define FETCH_xEOF 236 /* End Of File */
#define FETCH_SE 240   /* Sub negotiation End */
#define FETCH_NOP 241  /* No OPeration */
#define FETCH_DM 242   /* Data Mark */
#define FETCH_GA 249   /* Go Ahead, reverse the line */
#define FETCH_SB 250   /* SuBnegotiation */
#define FETCH_WILL 251 /* Our side WILL use this option */
#define FETCH_WONT 252 /* Our side will not use this option */
#define FETCH_DO 253   /* DO use this option! */
#define FETCH_DONT 254 /* DON'T use this option! */
#define FETCH_IAC 255  /* Interpret As Command */

#ifndef FETCH_DISABLE_VERBOSE_STRINGS
/*
 * Then those numbers represented as strings:
 */
static const char *const telnetcmds[] =
    {
        "EOF", "SUSP", "ABORT", "EOR", "SE",
        "NOP", "DMARK", "BRK", "IP", "AO",
        "AYT", "EC", "EL", "GA", "SB",
        "WILL", "WONT", "DO", "DONT", "IAC"};
#endif

#define FETCH_TELCMD_MINIMUM FETCH_xEOF /* the first one */
#define FETCH_TELCMD_MAXIMUM FETCH_IAC  /* surprise, 255 is the last one! ;-) */

#define FETCH_TELQUAL_IS 0
#define FETCH_TELQUAL_SEND 1
#define FETCH_TELQUAL_INFO 2
#define FETCH_TELQUAL_NAME 3

#define FETCH_TELCMD_OK(x) (((unsigned int)(x) >= FETCH_TELCMD_MINIMUM) && \
                            ((unsigned int)(x) <= FETCH_TELCMD_MAXIMUM))

#ifndef FETCH_DISABLE_VERBOSE_STRINGS
#define FETCH_TELCMD(x) telnetcmds[(x) - FETCH_TELCMD_MINIMUM]
#else
#define FETCH_TELCMD(x) ""
#endif

#endif /* FETCH_DISABLE_TELNET */

#endif /* HEADER_FETCH_ARPA_TELNET_H */
