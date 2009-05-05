# Process this file with autoconf to produce a configure script.

AC_INIT(sqlalias, 1.0.1, pierrick@webstart.fr, mod_sqlalias)
AC_PREREQ(2.53)
AC_COPYRIGHT([Copyright (c)2007 WebStart.fr.])
AC_CONFIG_SRCDIR([mod_sqlalias.c])
AC_CONFIG_HEADER([mod_sqlalias.h])

# Checks for programs.
AC_PROG_CC

AC_PATH_PROG(apxspath, apxs2, NOT_FOUND)
if test "x$apxspath" = xNOT_FOUND; then
	AC_MSG_ERROR([*** apxs2 not found.  Please install apxs2.])
fi

AC_PATH_PROG(apachectlpath, apache2ctl, NOT_FOUND)

# Check for headers
AC_C_CONST
AC_CHECK_HEADERS([unistd.h])

# Check for librarys 
AC_CHECK_LIB([m], [main])
AC_CHECK_LIB([mysqlclient], [mysql_real_connect], [], [
    AC_MSG_ERROR([*** mysqlclient not found.  Please install mysqlclient.])
])

# Check for functions

AC_CHECK_FUNCS([strchr], [], [
    AC_MSG_ERROR([*** strchr not found. Please install the string.h lib.])
])

# --width-debug
AC_ARG_WITH([debug],
            AC_HELP_STRING([--with-debug], [compile in debug mode (default is disabled)]),
            [debug_mode=$withval], [debug_mode=no]
)
AC_MSG_CHECKING([whether to compile in debug mode])
if test x$debug_mode != xno; then
	AC_MSG_RESULT([yes])
    AC_DEFINE(SQLALIAS_DEBUG, 1 ,[Define to 1 if you want to compile in debug mode])
else
	AC_MSG_RESULT([no])
fi

# --with-pconnect
AC_ARG_WITH([pconnect],
            AC_HELP_STRING([--with-pconnect], [compile with a mysql persistant connection (default is disabled)]),
            [pconnect_mode=$withval], [pconnect_mode=no]
)
AC_MSG_CHECKING([whether to use a mysql persistent connection])
if test x$pconnect_mode != xno; then
    AC_MSG_RESULT([yes])
    AC_DEFINE(SQLALIAS_USE_PCONNECT, 1, [Define to 1 if you want to use a mysql persistant connection])
else
    AC_MSG_RESULT([no])
fi

# --with-perfect-match
AC_ARG_WITH([perfect-match],
            AC_HELP_STRING([--with-perfect-match], [compile with URI perfect match (default is disabled)]),
            [pmatch=$withval], [pmatch=no]
)
AC_MSG_CHECKING([whether to do a perfect URI match])
if test x$pmatch != xno; then
    AC_MSG_RESULT([yes])
    AC_DEFINE(SQLALIAS_PERFECT_MATCH, 1, [Define to 1 if you want to do a perfect URI match])
else
    AC_MSG_RESULT([no])
fi        

cat >>confdefs.h <<_ACEOF
#define MODULE_NAME "$PACKAGE_NAME"
_ACEOF

cat >>confdefs.h <<_ACEOF
#define MODULE_VERSION "$PACKAGE_VERSION"
_ACEOF

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo
echo You can now run \'make\' and \'make install\'.
echo
