/* $Id$ */

#include "setup.h"
#include "ares_version.h"

const char *ares_version(int *version)
{
  if(version)
    *version = ARES_VERSION;

  return ARES_VERSION_STR;
}
