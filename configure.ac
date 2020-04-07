AC_PREREQ([2.64])

AC_INIT([wfw], [1.0], [youruid@wwu.edu])
AM_INIT_AUTOMAKE([silent-rules subdir-objects foreign])
AM_SILENT_RULES

AC_CONFIG_SRCDIR([src/wfw.c])
AC_CONFIG_HEADERS([config.h])


# Required Programs
#
AC_PROG_CC
AC_PROG_INSTALL

# Libraries
#
AC_CHECK_HEADERS([stdlib.h])
PKG_CHECK_MODULES([CHECK], [check >= 0.9.10])

# Files
#
AC_CONFIG_FILES([Makefile])


AC_OUTPUT
