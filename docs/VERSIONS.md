<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

Version Numbers and Releases
============================

 The command line tool curl and the library libcurl are individually
 versioned, but they usually follow each other closely.

 The version numbering is always built up using the same system:

        X.Y.Z

  - X is main version number
  - Y is release number
  - Z is patch number

## Bumping numbers

 One of these numbers get bumped in each new release. The numbers to the right
 of a bumped number are reset to zero.

 The main version number is bumped when *really* big, world colliding changes
 are made. The release number is bumped when changes are performed or
 things/features are added. The patch number is bumped when the changes are
 mere bugfixes.

 It means that after release 1.2.3, we can release 2.0.0 if something really
 big has been made, 1.3.0 if not that big changes were made or 1.2.4 if only
 bugs were fixed.

 Bumping, as in increasing the number with 1, is unconditionally only
 affecting one of the numbers (except the ones to the right of it, that may be
 set to zero). 1 becomes 2, 3 becomes 4, 9 becomes 10, 88 becomes 89 and 99
 becomes 100. So, after 1.2.9 comes 1.2.10. After 3.99.3, 3.100.0 might come.

 All original curl source release archives are named according to the libcurl
 version (not according to the curl client version that, as said before, might
 differ).

 As a service to any application that might want to support new libcurl
 features while still being able to build with older versions, all releases
 have the libcurl version stored in the `curl/curlver.h` file using a static
 numbering scheme that can be used for comparison. The version number is
 defined as:

```c
#define LIBCURL_VERSION_NUM 0xXXYYZZ
```

 Where `XX`, `YY` and `ZZ` are the main version, release and patch numbers in
 hexadecimal. All three number fields are always represented using two digits
 (eight bits each). 1.2 would appear as "0x010200" while version 9.11.7
 appears as `0x090b07`.

 This 6-digit hexadecimal number is always a greater number in a more recent
 release. It makes comparisons with greater than and less than work.

 This number is also available as three separate defines:
 `LIBCURL_VERSION_MAJOR`, `LIBCURL_VERSION_MINOR` and `LIBCURL_VERSION_PATCH`.

## Past releases

This is a list of all public releases with their version numbers and release
dates. The tool was called `httpget` before 2.0, `urlget` before 4.0 then
`curl` since 4.0. `libcurl` and `curl` are always released in sync, using the
same version numbers.

- 8.17.0: pending
- 8.16.0: September 10, 2025
- 8.15.0: July 16, 2025
- 8.14.1: June 4 2025
- 8.14.0: May 28 2025
- 8.13.0: April 2 2025
- 8.12.1: February 13 2025
- 8.12.0: February 5 2025
- 8.11.1: December 11 2024
- 8.11.0: November 6 2024
- 8.10.1: September 18 2024
- 8.10.0: September 11 2024
- 8.9.1: July 31 2024
- 8.9.0: July 24 2024
- 8.8.0: May 22 2024
- 8.7.1: March 27 2024
- 8.7.0: March 27 2024
- 8.6.0: January 31 2024
- 8.5.0: December 6 2023
- 8.4.0: October 11 2023
- 8.3.0: September 13 2023
- 8.2.1: July 26 2023
- 8.2.0: July 19 2023
- 8.1.2: May 30 2023
- 8.1.1: May 23 2023
- 8.1.0: May 17 2023
- 8.0.1: March 20 2023
- 8.0.0: March 20 2023
- 7.88.1: February 20 2023
- 7.88.0: February 15 2023
- 7.87.0: December 21 2022
- 7.86.0: October 26 2022
- 7.85.0: August 31 2022
- 7.84.0: June 27 2022
- 7.83.1: May 11 2022
- 7.83.0: April 27 2022
- 7.82.0: March 5 2022
- 7.81.0: January 5 2022
- 7.80.0: November 10 2021
- 7.79.1: September 22 2021
- 7.79.0: September 15 2021
- 7.78.0: July 21 2021
- 7.77.0: May 26 2021
- 7.76.1: April 14 2021
- 7.76.0: March 31 2021
- 7.75.0: February 3 2021
- 7.74.0: December 9 2020
- 7.73.0: October 14 2020
- 7.72.0: August 19 2020
- 7.71.1: July 1 2020
- 7.71.0: June 24 2020
- 7.70.0: April 29 2020
- 7.69.1: March 11 2020
- 7.69.0: March 4 2020
- 7.68.0: January 8 2020
- 7.67.0: November 6 2019
- 7.66.0: September 11 2019
- 7.65.3: July 19 2019
- 7.65.2: July 17 2019
- 7.65.1: June 5 2019
- 7.65.0: May 22 2019
- 7.64.1: March 27 2019
- 7.64.0: February 6 2019
- 7.63.0: December 12 2018
- 7.62.0: October 31 2018
- 7.61.1: September 5 2018
- 7.61.0: July 11 2018
- 7.60.0: May 16 2018
- 7.59.0: March 14 2018
- 7.58.0: January 24 2018
- 7.57.0: November 29 2017
- 7.56.1: October 23 2017
- 7.56.0: October 4 2017
- 7.55.1: August 14 2017
- 7.55.0: August 9 2017
- 7.54.1: June 14 2017
- 7.54.0: April 19 2017
- 7.53.1: February 24 2017
- 7.53.0: February 22 2017
- 7.52.1: December 23 2016
- 7.52.0: December 21 2016
- 7.51.0: November 2 2016
- 7.50.3: September 14 2016
- 7.50.2: September 7 2016
- 7.50.1: August 3 2016
- 7.50.0: July 21 2016
- 7.49.1: May 30 2016
- 7.49.0: May 18 2016
- 7.48.0: March 23 2016
- 7.47.1: February 8 2016
- 7.47.0: January 27 2016
- 7.46.0: December 2 2015
- 7.45.0: October 7 2015
- 7.44.0: August 12 2015
- 7.43.0: June 17 2015
- 7.42.1: April 29 2015
- 7.42.0: April 22 2015
- 7.41.0: February 25 2015
- 7.40.0: January 8 2015
- 7.39.0: November 5 2014
- 7.38.0: September 10 2014
- 7.37.1: July 16 2014
- 7.37.0: May 21 2014
- 7.36.0: March 26 2014
- 7.35.0: January 29 2014
- 7.34.0: December 17 2013
- 7.33.0: October 14 2013
- 7.32.0: August 12 2013
- 7.31.0: June 22 2013
- 7.30.0: April 12 2013
- 7.29.0: February 6 2013
- 7.28.1: November 20 2012
- 7.28.0: October 10 2012
- 7.27.0: July 27 2012
- 7.26.0: May 24 2012
- 7.25.0: March 22 2012
- 7.24.0: January 24 2012
- 7.23.1: November 17 2011
- 7.23.0: November 15 2011
- 7.22.0: September 13 2011
- 7.21.7: June 23 2011
- 7.21.6: April 22 2011
- 7.21.5: April 17 2011
- 7.21.4: February 17 2011
- 7.21.3: December 15 2010
- 7.21.2: October 13 2010
- 7.21.1: August 11 2010
- 7.21.0: June 16 2010
- 7.20.1: April 14 2010
- 7.20.0: February 9 2010
- 7.19.7: November 4 2009
- 7.19.6: August 12 2009
- 7.19.5: May 18 2009
- 7.19.4: March 3 2009
- 7.19.3: January 19 2009
- 7.19.2: November 13 2008
- 7.19.1: November 5 2008
- 7.19.0: September 1 2008
- 7.18.2: June 4 2008
- 7.18.1: March 30 2008
- 7.18.0: January 28 2008
- 7.17.1: October 29 2007
- 7.17.0: September 13 2007
- 7.16.4: July 10 2007
- 7.16.3: June 25 2007
- 7.16.2: April 11 2007
- 7.16.1: January 29 2007
- 7.16.0: October 30 2006
- 7.15.5: August 7 2006
- 7.15.4: June 12 2006
- 7.15.3: March 20 2006
- 7.15.2: February 27 2006
- 7.15.1: December 7 2005
- 7.15.0: October 13 2005
- 7.14.1: September 1 2005
- 7.14.0: May 16 2005
- 7.13.2: April 4 2005
- 7.13.1: March 4 2005
- 7.13.0: February 1 2005
- 7.12.3: December 20 2004
- 7.12.2: October 18 2004
- 7.12.1: August 10 2004
- 7.12.0: June 2 2004
- 7.11.2: April 26 2004
- 7.11.1: March 19 2004
- 7.11.0: January 22 2004
- 7.10.8: November 1 2003
- 7.10.7: August 15 2003
- 7.10.6: July 28 2003
- 7.10.5: May 19 2003
- 7.10.4: April 2 2003
- 7.10.3: January 14 2003
- 7.10.2: November 18 2002
- 7.10.1: October 11 2002
- 7.10: October 1 2002
- 7.9.8: June 13 2002
- 7.9.7: May 10 2002
- 7.9.6: April 14 2002
- 7.9.5: March 7 2002
- 7.9.4: March 4 2002
- 7.9.3: January 23 2002
- 7.9.2: December 5 2001
- 7.9.1: November 4 2001
- 7.9: September 23 2001
- 7.8.1: August 20 2001
- 7.8: June 7 2001
- 7.7.3: May 4 2001
- 7.7.2: April 22 2001
- 7.7.1: April 3 2001
- 7.7: March 22 2001
- 7.6.1: February 9 2001
- 7.6: January 26 2001
- 7.5.2: January 4 2001
- 7.5.1: December 11 2000
- 7.5: December 1 2000
- 7.4.2: November 15 2000
- 7.4.1: October 16 2000
- 7.4: October 16 2000
- 7.3: September 28 2000
- 7.2.1: August 31 2000
- 7.2: August 30 2000
- 7.1.1: August 21 2000
- 7.1: August 7 2000
- 6.5.2: March 21 2000
- 6.5.1: March 20 2000
- 6.5: March 13 2000
- 6.4: January 17 2000
- 6.3.1: November 23 1999
- 6.3: November 10 1999
- 6.2: October 21 1999
- 6.1: October 17 1999
- 6.0: September 13 1999
- 5.11: August 25 1999
- 5.10: August 13 1999
- 5.9.1: July 30 1999
- 5.9: May 22 1999
- 5.8: May 5 1999
- 5.7.1: April 23 1999
- 5.7: April 20 1999
- 5.5.1: January 27 1999
- 5.5: January 15 1999
- 5.4: January 7 1999
- 5.3: December 21 1998
- 5.2.1: December 14 1998
- 5.2: December 14 1998
- 5.0: December 1 1998
- 4.10: October 26 1998
- 4.9: October 7 1998
- 4.8.4: September 20 1998
- 4.8.3: September 7 1998
- 4.8.2: August 14 1998
- 4.8.1: August 7 1998
- 4.8: July 30 1998
- 4.7: July 20 1998
- 4.6: July 3 1998
- 4.5.1: June 12 1998
- 4.5: May 30 1998
- 4.4: May 13 1998
- 4.3: April 30 1998
- 4.2: April 15 1998
- 4.1: April 3 1998
- 4.0: March 20 1998
- 3.12: March 14 1998
- 3.11: February 9 1998
- 3.10: February 4 1998
- 3.9: February 4 1998
- 3.7: January 15 1998
- 3.6: January 1 1998
- 3.5: December 15 1997
- 3.2: December 1 1997
- 3.1: November 24 1997
- 3.0: November 1 1997
- 2.9: October 15 1997
- 2.8: October 1 1997
- 2.7: September 20 1997
- 2.6: September 10 1997
- 2.5: September 1 1997
- 2.4: August 27 1997
- 2.3: August 21 1997
- 2.2: August 14 1997
- 2.1: August 10 1997
- 2.0: August 1 1997
- 1.5: July 21 1997
- 1.4: July 15 1997
- 1.3: June 1 1997
- 1.2: May 1 1997
- 1.1: April 20 1997
- 1.0: April 8 1997
- 0.3: February 1 1997
- 0.2: December 17 1996
- 0.1: November 11 1996
