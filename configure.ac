#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([dtscon], [0.1], [gregory@distrotech.co.za])
AC_CONFIG_SRCDIR([src/newt.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
LT_INIT()

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

AC_ARG_ENABLE([dev-mode], AS_HELP_STRING([--enable-dev-mode], [Developer mode -g -Wall -Werror -pedantic-errors]))
if test "x$enable_dev_mode" = "xyes" ; then
 DEVELOPER_CFLAGS="-g -Wall -Werror -pedantic-errors -Wno-overlength-strings"
fi;
AC_SUBST(DEVELOPER_CFLAGS)

AC_ARG_ENABLE([world-peace], AS_HELP_STRING([--enable-world-peace], [Yeah right .....]))

# Checks for libraries.
AC_CHECK_LIB([m], [pow], [], [AC_MSG_ERROR([Requires Math Lib -lm])])
PKG_CHECK_MODULES(FWORK, framework >= 0)
PKG_CHECK_MODULES(SLANG, slang >= 2.2)
PKG_CHECK_MODULES(NEWT, libnewt >= 0.52)
PKG_CHECK_MODULES(CURL, libcurl >= 7)

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h sys/ioctl.h termios.h fcntl.h arpa/inet.h ldap.h sasl/sasl.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT8_T
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT32_T

# Checks for library functions. 
AC_CHECK_FUNCS([mkdir strdup pow localtime_r floor])
AC_FUNC_MALLOC
AC_FUNC_CHOWN

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
