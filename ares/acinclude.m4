
dnl We create a function for detecting which compiler we use and then set as
dnl pendantic compiler options as possible for that particular compiler. The
dnl options are only used for debug-builds.

dnl This is a copy of the original found in curl's configure script. Don't
dnl modify this one, edit the one in curl and copy it back here when that one
dnl is changed.

AC_DEFUN([CURL_CC_DEBUG_OPTS],
[
    if test "$GCC" = "yes"; then

       dnl figure out gcc version!
       AC_MSG_CHECKING([gcc version])
       gccver=`$CC -dumpversion`
       num1=`echo $gccver | cut -d . -f1`
       num2=`echo $gccver | cut -d . -f2`
       gccnum=`(expr $num1 "*" 100 + $num2) 2>/dev/null`
       AC_MSG_RESULT($gccver)

       AC_MSG_CHECKING([if this is icc in disguise])
       AC_EGREP_CPP([^__ICC], [__ICC],
         dnl action if the text is found, this it has not been replaced by the
         dnl cpp
         [ICC="no"]
         AC_MSG_RESULT([no]),
         dnl the text was not found, it was replaced by the cpp
         [ICC="yes"]
         AC_MSG_RESULT([yes])
       )

       if test "$ICC" = "yes"; then
         dnl this is icc, not gcc.

         dnl Warning 279 warns on static conditions in while expressions,
         dnl ignore that.

         WARN="-wd279"

         if test "$gccnum" -gt "600"; then
            dnl icc 6.0 and older doesn't have the -Wall flag, although it does
            dnl have -wd<n>
            WARN="-Wall $WARN"
         fi
       else dnl $ICC = yes
         dnl 
         WARN="-W -Wall -Wwrite-strings -pedantic -Wno-long-long -Wundef -Wpointer-arith -Wnested-externs -Winline -Wmissing-declarations -Wmissing-prototypes -Wsign-compare"

         dnl -Wcast-align is a bit too annoying ;-)

         if test "$gccnum" -ge "296"; then
           dnl gcc 2.96 or later
           WARN="$WARN -Wfloat-equal"

           if test "$gccnum" -gt "296"; then
             dnl this option does not exist in 2.96
             WARN="$WARN -Wno-format-nonliteral"
           fi

           dnl -Wunreachable-code seems totally unreliable on my gcc 3.3.2 on
           dnl on i686-Linux as it gives us heaps with false positives
           if test "$gccnum" -ge "303"; then
             dnl gcc 3.3 and later
             WARN="$WARN -Wendif-labels -Wstrict-prototypes"
           fi
         fi

         for flag in $CPPFLAGS; do
           case "$flag" in
            -I*)
              dnl include path
              add=`echo $flag | sed 's/^-I/-isystem /g'`
              WARN="$WARN $add"
              ;;
           esac
         done

       fi dnl $ICC = no

       CFLAGS="$CFLAGS $WARN"

    fi dnl $GCC = yes

    dnl strip off optimizer flags
    NEWFLAGS=""
    for flag in $CFLAGS; do
      case "$flag" in
      -O*)
        dnl echo "cut off $flag"
        ;;
      *)
        NEWFLAGS="$NEWFLAGS $flag"
        ;;
      esac
    done
    CFLAGS=$NEWFLAGS

]) dnl end of AC_DEFUN()

