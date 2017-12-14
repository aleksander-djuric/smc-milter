AC_INIT([smc-milter], [2.2], [info@true-audio.com])
AC_CANONICAL_TARGET

AC_CONFIG_SRCDIR([smc-milter.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE

CFLAGS="-w -O2 -D_GNU_SOURCE -D_REENTRANT"
LIBS="-pthread"

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# System dependent checks
AC_C_BIGENDIAN

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_RESOLV
AC_HEADER_TIME
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdlib.h string.h sys/file.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for libraries.
AC_MSG_CHECKING(for bind libraries)
AC_ARG_WITH(bind,
[  --with-bind[=DIR]	  use libbind instead of libresolv],
[
    if test "$withval" != "no"; then
	if test "$withval" = "yes"; then
	    if test -f /usr/lib/bind/lib/libbind_r.a; then
		BIND_INCDIR=/usr/lib/bind/include
		BIND_LIBDIR=/usr/lib/bind/lib
	    elif test -f /usr/local/bind/lib/libbind_r.a; then
	    	BIND_INCDIR=/usr/local/bind/include
		BIND_LIBDIR=/usr/local/bind/lib
	    else
		AC_MSG_RESULT(no)
		AC_MSG_ERROR(Can't find bind libraries)
	    fi
	else 
	    if test -f $withval/lib/libbind_r.a; then
		BIND_INCDIR=$withval/include
		BIND_LIBDIR=$withval/lib
	    else
		AC_MSG_RESULT(no)
		AC_MSG_ERROR(Can't find bind libraries in $withval)
	    fi
	fi

	AC_MSG_RESULT(yes)
	CFLAGS="$CFLAGS -I$BIND_INCDIR"
	LIBS="$LIBS $BIND_LIBDIR/libbind_r.a"
    fi
],[
    AC_MSG_RESULT(no)
    AC_CHECK_LIB(resolv, __res_ninit)
])

AC_ARG_WITH(spf2-lib,
[  --with-spf2-lib=DIR	  specify spf2 library location],
[
    LDFLAGS=$LDFLAGS" -L$withval/lib"
    CFLAGS=$CFLAGS" -I$withval/include"
])

AC_ARG_WITH(spf2,
    [  --without-spf2	  build without spf2 support],
    [ with_spf2=$withval ],
    [ with_spf2=yes ])

if test "$with_spf2" == "yes"
then
    AC_CHECK_LIB(spf2, SPF_server_new,, [AC_MSG_ERROR([Couldn't find spf2 library])])
fi

AC_CHECK_LIB(pthread, pthread_mutex_init,, AC_MSG_ERROR([POSIX thread support not installed]))
AC_CHECK_LIB(ssl, SSL_library_init,, AC_MSG_ERROR([Required SSL library not found]))
AC_CHECK_LIB(milter, smfi_register,, AC_MSG_ERROR([Required MILTER library not found]))
AC_CHECK_LIB(crypto, MD5_Init, [], [AC_CHECK_LIB(ssl, MD5_Init)])

# Checks for library functions.
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MMAP
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([memchr memmove memset munmap regcomp select socket strcasecmp strchr strdup strerror strncasecmp strrchr])

if test "$prefix" = "NONE"; then prefix=""; fi
eval CONFIG_FILE="${sysconfdir}/smc-milter.conf"
eval USERS_FILE="${sysconfdir}/smc-milter.users"
eval HOSTS_FILE="${sysconfdir}/smc-milter.hosts"
eval SOCKET_FILE="${localstatedir}/lib/smc-milter/smc-milter.sock"
eval CACHE_FILE="${localstatedir}/lib/smc-milter/smc-milter.dat"
eval PID_FILE="${localstatedir}/run/smc-milter/smc-milter.pid"
eval TMP_FILE="${localstatedir}/tmp/smc-file.XXXXXX"
eval CLAMD_SOCKET_FILE="/var/lib/clamav/clamd.socket"

AC_DEFINE_UNQUOTED(CONFIG_FILE, ["$CONFIG_FILE"], [SMC milter configuration file.])
AC_DEFINE_UNQUOTED(USERS_FILE, ["$USERS_FILE"], [SMC milter users file.])
AC_DEFINE_UNQUOTED(HOSTS_FILE, ["$HOSTS_FILE"], [SMC milter hosts file.])
AC_DEFINE_UNQUOTED(SOCKET_FILE, ["$SOCKET_FILE"], [SMC milter socket file.])
AC_DEFINE_UNQUOTED(CLAMD_SOCKET_FILE, ["$CLAMD_SOCKET_FILE"], [ClamAV socket file.])
AC_DEFINE_UNQUOTED(PID_FILE, ["$PID_FILE"], [SMC milter pid file.])
AC_DEFINE_UNQUOTED(TMP_FILE, ["$TMP_FILE"], [SMC milter temporary file.])
AC_DEFINE_UNQUOTED(CACHE_FILE, ["$CACHE_FILE"], [SMC milter cache file.])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
