dnl Process this file with autoconf to produce configure.

AC_INIT(purple-otr, 3.2.1)

AC_CONFIG_HEADERS(config.h)

AM_INIT_AUTOMAKE([-Wall])

AC_PROG_CC

dnl We do not want to create a .a for the plugin, so disable by default.
AM_DISABLE_STATIC
AM_PROG_LIBTOOL

AM_PATH_LIBGCRYPT(1:1.2.0,,AC_MSG_ERROR(libgcrypt 1.2.0 or newer is required.))

AM_PATH_LIBOTR3(3.2.0,,AC_MSG_ERROR(libotr3 3.2.0 or newer is required.))

PKG_CHECK_MODULES([EXTRA], [glib-2.0 >= 2.6 gtk+-2.0 >= 2.6 pidgin >= 2.10 purple >= 2.0])

AC_PROG_INTLTOOL

GETTEXT_PACKAGE=purple-otr
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, ["$GETTEXT_PACKAGE"], [Define the gettext package to be used])

ALL_LINGUAS="ar de es fr hu nl ru sk"
AM_GLIB_GNU_GETTEXT

AC_OUTPUT([Makefile po/Makefile.in])
