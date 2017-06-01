# ===========================================================================
#     http://www.gnu.org/software/autoconf-archive/ax_code_coverage.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_CODE_COVERAGE()
#
# DESCRIPTION
#
#   Defines CODE_COVERAGE_CFLAGS and CODE_COVERAGE_LDFLAGS which should be
#   included in the CFLAGS and LIBS/LDFLAGS variables of every build target
#   (program or library) which should be built with code coverage support.
#   Also defines CODE_COVERAGE_RULES which should be substituted in your
#   Makefile; and $enable_code_coverage which can be used in subsequent
#   configure output. CODE_COVERAGE_ENABLED is defined and substituted, and
#   corresponds to the value of the --enable-code-coverage option, which
#   defaults to being disabled.
#
#   Test also for gcov program and create GCOV variable that could be
#   substituted.
#
#   Note that all optimisation flags in CFLAGS must be disabled when code
#   coverage is enabled.
#
#   Usage example:
#
#   configure.ac:
#
#     AX_CODE_COVERAGE
#
#   Makefile.am:
#
#     @CODE_COVERAGE_RULES@
#     my_program_LIBS = ... $(CODE_COVERAGE_LDFLAGS) ...
#     my_program_CFLAGS = ... $(CODE_COVERAGE_CFLAGS) ...
#
#   This results in a "check-code-coverage" rule being added to any
#   Makefile.am which includes "@CODE_COVERAGE_RULES@" (assuming the module
#   has been configured with --enable-code-coverage). Running `make
#   check-code-coverage` in that directory will run the module's test suite
#   (`make check`) and build a code coverage report detailing the code which
#   was touched, then print the URI for the report.
#
#   This code was derived from Makefile.decl in GLib, originally licenced
#   under LGPLv2.1+.
#
# LICENSE
#
#   Copyright (c) 2012 Philip Withnall
#   Copyright (c) 2012 Xan Lopez
#   Copyright (c) 2012 Christian Persch
#   Copyright (c) 2012 Paolo Borelli
#   Copyright (c) 2012 Dan Winship
#   Copyright (c) 2015 Bastien ROUCARIES
#
#   This library is free software; you can redistribute it and/or modify it
#   under the terms of the GNU Lesser General Public License as published by
#   the Free Software Foundation; either version 2.1 of the License, or (at
#   your option) any later version.
#
#   This library is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
#   General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public License
#   along with this program. If not, see <http://www.gnu.org/licenses/>.

#serial 5

AC_DEFUN([AX_CODE_COVERAGE],[
	dnl Check for --enable-code-coverage
	AC_REQUIRE([AC_PROG_SED])

	# allow to override gcov location
	AC_ARG_WITH([gcov],
	  [AS_HELP_STRING([--with-gcov[=GCOV]], [use given GCOV for coverage (GCOV=gcov).])],
	  [_AX_CODE_COVERAGE_GCOV_PROG_WITH=$with_gcov],
	  [_AX_CODE_COVERAGE_GCOV_PROG_WITH=gcov])

	AC_MSG_CHECKING([whether to build with code coverage support])
	AC_ARG_ENABLE([code-coverage],
	  AS_HELP_STRING([--enable-code-coverage],
	  [Whether to enable code coverage support]),,
	  enable_code_coverage=no)

	AM_CONDITIONAL([CODE_COVERAGE_ENABLED], [test x$enable_code_coverage = xyes])
	AC_SUBST([CODE_COVERAGE_ENABLED], [$enable_code_coverage])
	AC_MSG_RESULT($enable_code_coverage)

	AS_IF([ test "$enable_code_coverage" = "yes" ], [
		# check for gcov
		AC_CHECK_TOOL([GCOV],
		  [$_AX_CODE_COVERAGE_GCOV_PROG_WITH],
		  [:])
		AS_IF([test "X$GCOV" = "X:"],
		  [AC_MSG_ERROR([gcov is needed to do coverage])])
		AC_SUBST([GCOV])

		dnl Check if gcc is being used
		AS_IF([ test "$GCC" = "no" ], [
			AC_MSG_ERROR([not compiling with gcc, which is required for gcov code coverage])
		])

		# List of supported lcov versions.
		lcov_version_list="1.6 1.7 1.8 1.9 1.10 1.11 1.13"

		AC_CHECK_PROG([LCOV], [lcov], [lcov])
		AC_CHECK_PROG([GENHTML], [genhtml], [genhtml])

		AS_IF([ test "$LCOV" ], [
			AC_CACHE_CHECK([for lcov version], ax_cv_lcov_version, [
				ax_cv_lcov_version=invalid
				lcov_version=`$LCOV -v 2>/dev/null | $SED -e 's/^.* //'`
				for lcov_check_version in $lcov_version_list; do
					if test "$lcov_version" = "$lcov_check_version"; then
						ax_cv_lcov_version="$lcov_check_version (ok)"
					fi
				done
			])
		], [
			lcov_msg="To enable code coverage reporting you must have one of the following lcov versions installed: $lcov_version_list"
			AC_MSG_ERROR([$lcov_msg])
		])

		case $ax_cv_lcov_version in
			""|invalid[)]
				lcov_msg="You must have one of the following versions of lcov: $lcov_version_list (found: $lcov_version)."
				AC_MSG_ERROR([$lcov_msg])
				LCOV="exit 0;"
			;;
		esac

		AS_IF([ test -z "$GENHTML" ], [
			AC_MSG_ERROR([Could not find genhtml from the lcov package])
		])

		dnl Build the code coverage flags
		CODE_COVERAGE_CFLAGS="-O0 -g -fprofile-arcs -ftest-coverage"
		CODE_COVERAGE_LDFLAGS="-lgcov"

		AC_SUBST([CODE_COVERAGE_CFLAGS])
		AC_SUBST([CODE_COVERAGE_LDFLAGS])

CODE_COVERAGE_RULES='
# Code coverage
#
# Optional:
#  - CODE_COVERAGE_DIRECTORY: Top-level directory for code coverage reporting.
#    (Default: $(top_builddir))
#  - CODE_COVERAGE_OUTPUT_FILE: Filename and path for the .info file generated
#    by lcov for code coverage. (Default:
#    $(PACKAGE_NAME)-$(PACKAGE_VERSION)-coverage.info)
#  - CODE_COVERAGE_OUTPUT_DIRECTORY: Directory for generated code coverage
#    reports to be created. (Default:
#    $(PACKAGE_NAME)-$(PACKAGE_VERSION)-coverage)
#  - CODE_COVERAGE_LCOV_OPTIONS_GCOVPATH: --gcov-tool pathtogcov
#  - CODE_COVERAGE_LCOV_OPTIONS_DEFAULT: Extra options to pass to the lcov instance.
#    (Default: $CODE_COVERAGE_LCOV_OPTIONS_GCOVPATH)
#  - CODE_COVERAGE_LCOV_OPTIONS: Extra options to pass to the lcov instance.
#    (Default: $CODE_COVERAGE_LCOV_OPTIONS_DEFAULT)
#  - CODE_COVERAGE_GENHTML_OPTIONS: Extra options to pass to the genhtml
#    instance. (Default: empty)
#  - CODE_COVERAGE_IGNORE_PATTERN: Extra glob pattern of files to ignore
#
# The generated report will be titled using the $(PACKAGE_NAME) and
# $(PACKAGE_VERSION). In order to add the current git hash to the title,
# use the git-version-gen script, available online.

# Optional variables
CODE_COVERAGE_DIRECTORY ?= $(top_builddir)
CODE_COVERAGE_OUTPUT_FILE ?= $(PACKAGE_NAME)-$(PACKAGE_VERSION)-coverage.info
CODE_COVERAGE_OUTPUT_DIRECTORY ?= $(PACKAGE_NAME)-$(PACKAGE_VERSION)-coverage
CODE_COVERAGE_LCOV_OPTIONS_GCOVPATH ?= --gcov-tool "$(GCOV)"
CODE_COVERAGE_LCOV_OPTIONS_DEFAULT ?= $(CODE_COVERAGE_LCOV_OPTIONS_GCOVPATH)
CODE_COVERAGE_LCOV_OPTIONS ?= $(CODE_COVERAGE_LCOV_OPTIONS_DEFAULT)
CODE_COVERAGE_GENHTML_OPTIONS ?=
CODE_COVERAGE_IGNORE_PATTERN ?=

code_coverage_quiet = $(code_coverage_quiet_$(V))
code_coverage_quiet_ =
code_coverage_quiet_0 = --quiet

# Use recursive makes in order to ignore errors during check
check-code-coverage:
	-$(MAKE) $(AM_MAKEFLAGS) -k check
	$(MAKE) $(AM_MAKEFLAGS) code-coverage-capture

# Capture code coverage data
code-coverage-capture: code-coverage-capture-hook
	$(LCOV) $(code_coverage_quiet) --directory $(CODE_COVERAGE_DIRECTORY) --capture --output-file "$(CODE_COVERAGE_OUTPUT_FILE).tmp" --test-name "$(PACKAGE_NAME)-$(PACKAGE_VERSION)" --no-checksum --compat-libtool $(CODE_COVERAGE_LCOV_OPTIONS)
	$(LCOV) $(code_coverage_quiet) --directory $(CODE_COVERAGE_DIRECTORY) --remove "$(CODE_COVERAGE_OUTPUT_FILE).tmp" "/tmp/*" $(CODE_COVERAGE_IGNORE_PATTERN) --output-file "$(CODE_COVERAGE_OUTPUT_FILE)"
	-@rm -f $(CODE_COVERAGE_OUTPUT_FILE).tmp
	LANG=C $(GENHTML) $(code_coverage_quiet) --prefix $(CODE_COVERAGE_DIRECTORY) --output-directory "$(CODE_COVERAGE_OUTPUT_DIRECTORY)" --title "$(PACKAGE_NAME)-$(PACKAGE_VERSION) Code Coverage" --legend --show-details "$(CODE_COVERAGE_OUTPUT_FILE)" $(CODE_COVERAGE_GENHTML_OPTIONS)
	@echo "file://$(abs_builddir)/$(CODE_COVERAGE_OUTPUT_DIRECTORY)/index.html"

# Hook rule executed before code-coverage-capture, overridable by the user
code-coverage-capture-hook:

clean: code-coverage-clean
code-coverage-clean:
	-$(LCOV) --directory $(top_builddir) -z
	-rm -rf $(CODE_COVERAGE_OUTPUT_FILE) $(CODE_COVERAGE_OUTPUT_FILE).tmp $(CODE_COVERAGE_OUTPUT_DIRECTORY)
	-find . -name "*.gcda" -o -name "*.gcov" -delete

GITIGNOREFILES ?=
GITIGNOREFILES += $(CODE_COVERAGE_OUTPUT_FILE) $(CODE_COVERAGE_OUTPUT_DIRECTORY)

DISTCHECK_CONFIGURE_FLAGS ?=
DISTCHECK_CONFIGURE_FLAGS += --disable-code-coverage

.PHONY: check-code-coverage code-coverage-capture code-coverage-capture-hook code-coverage-clean
'
	AC_SUBST([CODE_COVERAGE_RULES])
	])

	m4_ifdef([_AM_SUBST_NOTMAKE], [_AM_SUBST_NOTMAKE([CODE_COVERAGE_RULES])])
])
