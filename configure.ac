AC_PREREQ([2.63])
AC_INIT(xeert, 1.0.0)
AC_CONFIG_HEADERS([src/config.h])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX

# Checks for external libraries.
PKG_CHECK_MODULES(OPENSSL, openssl >= 3)

AC_CONFIG_FILES([Makefile test/Makefile])
AC_OUTPUT

