/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 *  Contributor(s):
 *   Rafael Sagula <sagula@inf.ufrgs.br>
 *   Sampo Kellomaki <sampo@iki.fi>
 *   Linas Vepstas <linas@linas.org>
 *   Bjorn Reese <breese@imada.ou.dk>
 *   Johan Anderson <johan@homemail.com>
 *   Kjell Ericson <Kjell.Ericson@haxx.nu>
 *   Troy Engel <tengel@palladium.net>
 *   Ryan Nelson <ryan@inch.com>
 *   Bjorn Stenberg <Bjorn.Stenberg@haxx.nu>
 *   Angus Mackay <amackay@gus.ml.org>
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 * $Log$
 * Revision 1.2  2000-01-10 23:36:14  bagder
 * syncing with local edit
 *
 * Revision 1.4  1999/09/06 06:59:40  dast
 * Changed email info
 *
 * Revision 1.3  1999/08/13 07:34:48  dast
 * Changed the URL in the header
 *
 * Revision 1.2  1999/03/13 00:56:09  dast
 * Big changes done due to url.c being split up in X smaller files and that
 * the lib is now more stand-alone.
 *
 * Revision 1.1.1.1  1999/03/11 22:23:34  dast
 * Imported sources
 *
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#ifdef WIN32
#include <windows.h>
#endif

char *GetEnv(char *variable)
{
#ifdef WIN32
  /* This shit requires windows.h (HUGE) to be included */
  static char env[MAX_PATH]; /* MAX_PATH is from windef.h */
  char *temp = getenv(variable);
  env[0] = '\0';
  ExpandEnvironmentStrings(temp, env, sizeof(env));
#else
  /* no length control */
  char *env = getenv(variable);
#endif
  return env;
}

char *curl_GetEnv(char *v)
{
  return GetEnv(v);
}
