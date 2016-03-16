#
#

PKGADD_PKG="@PKGADD_PKG@"
PKGADD_NAME="@PACKAGE@-@VERSION@ - @PKGADD_NAME@"
PKGADD_VENDOR="@PKGADD_VENDOR@"
PKGADD_ARCH="@host_cpu@"
PKGADD_DESC="@PACKAGE@-@VERSION@ - @PKGADD_NAME@"
PKGADD_CLASSES=none
PKGADD_BASEDIR=/

PKGADD_FILE=${PKGADD_PKG}-@PACKAGE@-@VERSION@-@host@.pkg

package:
	if [ ! -f release ]; then echo 0 > release; fi
	if [ `find root -newer release -print|wc -l` -gt 0 ]; then expr `cat release` + 1 > release; fi
	echo PKG=${PKGADD_PKG} > pkginfo
	echo NAME=${PKGADD_NAME} >> pkginfo
	echo VENDOR=${PKGADD_VENDOR} >> pkginfo
	echo ARCH=${PKGADD_ARCH} >> pkginfo
	echo DESC=${PKGADD_DESC} >> pkginfo
	echo CLASSES=${PKGADD_CLASSES} >> pkginfo
	echo BASEDIR=${PKGADD_BASEDIR} >> pkginfo
	echo CATEGORY=application >> pkginfo
	echo VERSION=`cat ./release` >> pkginfo
	echo > prototype
	for subdir in opt var etc usr; \
	do if [ -d root/$$subdir ]; then \
		pkgproto root/$$subdir=$$subdir >> prototype;\
	fi; done
	for file in pkginfo preinstall postinstall copyright; \
	do if [ -f $$file ]; then \
		echo "i $$file=$$file" >> prototype; \
	fi; done
	rm -rf ./tmp
	mkdir ./tmp
	pkgmk -o -d ./tmp
	pkgtrans -so ./tmp ${top_srcdir}/../${PKGADD_FILE} ${PKGADD_PKG}
