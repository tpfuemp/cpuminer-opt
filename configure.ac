AC_INIT([cpuminer-opt], [26.1])

AC_PREREQ([2.59c])
AC_CANONICAL_SYSTEM
AC_CONFIG_SRCDIR([cpu-miner.c])
AC_CONFIG_HEADERS([cpuminer-config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects])

dnl Make sure anyone changing configure.ac/Makefile.am has a clue
AM_MAINTAINER_MODE

dnl Checks for programs
AC_PROG_CC_C99
AC_PROG_GCC_TRADITIONAL
AM_PROG_CC_C_O
AM_PROG_AS
AC_PROG_RANLIB
AC_PROG_CXX

dnl Checks for header files
AC_HEADER_STDC
AC_CHECK_HEADERS([sys/endian.h sys/param.h syslog.h])
# sys/sysctl.h requires sys/types.h on FreeBSD
# sys/sysctl.h requires sys/param.h on OpenBSD
AC_CHECK_HEADERS([sys/sysctl.h], [], [],
[#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
])

AC_CHECK_DECLS([be32dec, le32dec, be32enc, le32enc, le16dec, le16enc], [], [],
[AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
])

AC_FUNC_ALLOCA
AC_CHECK_FUNCS([getopt_long])

case $target in
  x86_64-*-*|amd64-*-*)
    have_x86_64=true
    ;;
  aarch64*-*-*|arm64*-*-*)
    have_arm64=true
    ;;
  powerpc*-*-*)
    have_ppc=true
    ;;
esac

# The ARMv8 crypto extension is selected at compile time only: the hardware AES
# and SHA-256 paths are gated on __ARM_FEATURE_AES/__ARM_FEATURE_SHA2 with no
# runtime fallback, so a build with no arch flag silently drops all of them.
# Add one when the CPU has the extension and the user has not already chosen a
# -march/-mcpu. Only /proc/cpuinfo may enable +crypto: a flag that merely
# compiles proves nothing about the CPU, and guessing wrong is a SIGILL.
if test x$have_arm64 = xtrue; then
  arm_user_arch=no
  case " $CFLAGS " in
    *" -march="*|*" -mcpu="*) arm_user_arch=yes ;;
  esac
  AC_MSG_CHECKING([aarch64 architecture flags])
  if test x$arm_user_arch = xyes; then
    AC_MSG_RESULT([set in CFLAGS, unchanged])
  elif test x$cross_compiling = xyes; then
    AC_MSG_RESULT([none, cross compiling: pass CFLAGS=-march=...])
  else
    arm_feat=`grep -m1 -i '^Features' /proc/cpuinfo 2>/dev/null`
    arm_cands=
    case $arm_feat in
      *aes*pmull*|*pmull*aes*)
        case $arm_feat in
          *sha3*) arm_cands="-march=armv8-a+crypto+sha3" ;;
        esac
        arm_cands="$arm_cands -march=armv8-a+crypto"
        ;;
    esac
    arm_arch=
    arm_save_cflags="$CFLAGS"
    for arm_cand in $arm_cands; do
      CFLAGS="$arm_save_cflags $arm_cand"
      dnl Require the feature macros, not just a flag the driver accepts.
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if !defined(__ARM_FEATURE_AES) || !defined(__ARM_FEATURE_SHA2)
#error arch flag did not enable the crypto extension
#endif
      ]], [[]])], [arm_arch="$arm_cand"])
      test -n "$arm_arch" && break
    done
    CFLAGS="$arm_save_cflags"
    if test -n "$arm_arch"; then
      CFLAGS="$CFLAGS $arm_arch"
      AC_MSG_RESULT([$arm_arch])
    else
      AC_MSG_RESULT([none, no ARM crypto extension reported: pass CFLAGS=-march=... to override])
    fi
  fi
fi

PTHREAD_FLAGS="-pthread"
WS2_LIBS=""

case $target in
  *-*-mingw*)
    have_win32=true
    PTHREAD_FLAGS=""
    WS2_LIBS="-lws2_32"
    ;;
  *-apple-*)
    have_apple=true
    ;;
esac

AC_ARG_ENABLE([assembly],
  AS_HELP_STRING([--disable-assembly], [disable assembly-language routines]))
if test x$enable_assembly != xno; then
  AC_DEFINE([USE_ASM], [1], [Define to 1 if assembly routines are wanted.])
fi

# jansson test fails on Linux/Mingw, handled in Makefile.am.
AC_CHECK_LIB(jansson, json_loads, request_jansson=false, request_jansson=true)

AC_CHECK_LIB([pthread], [pthread_create], PTHREAD_LIBS="-lpthread",
  AC_CHECK_LIB([pthreadGC2], [pthread_create], PTHREAD_LIBS="-lpthreadGC2",
    AC_CHECK_LIB([pthreadGC1], [pthread_create], PTHREAD_LIBS="-lpthreadGC1",
      AC_CHECK_LIB([pthreadGC], [pthread_create], PTHREAD_LIBS="-lpthreadGC"
))))

AC_MSG_CHECKING(whether __uint128_t is supported)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([static __uint128_t i = 100;])],
      AC_DEFINE(USE_INT128, 1, [Define if __uint128_t is available])
      AC_MSG_RESULT(yes)
    ,
      AC_MSG_RESULT(no)
)

# allow if <var> in Makefile.am
AM_CONDITIONAL([WANT_JANSSON], [test x$request_jansson = xtrue])
AM_CONDITIONAL([HAVE_WINDOWS], [test x$have_win32 = xtrue])
AM_CONDITIONAL([USE_ASM], [test x$enable_assembly != xno])
AM_CONDITIONAL([ARCH_x86_64], [test x$have_x86_64 = xtrue])
AM_CONDITIONAL([ARCH_ARM64], [test x$have_arm64 = xtrue])
AM_CONDITIONAL([MINGW], [test "x$OS" = "xWindows_NT"])
AM_CONDITIONAL([HAVE_APPLE], [test x$have_apple = xtrue])

# libcurl install path (for mingw : --with-curl=/usr/local)
AC_ARG_WITH([curl],
   [  --with-curl=PATH         prefix where curl is installed [default=/usr]])

if test -n "$with_curl" ; then
   LIBCURL_CFLAGS="$LIBCURL_CFLAGS -I$with_curl/include"
   LIBCURL_CPPFLAGS="$LIBCURL_CPPFLAGS -I$with_curl/include"
   LIBCURL_LDFLAGS="-L$with_curl/lib $LIBCURL_LDFLAGS"
   LIBCURL="-lcurl -lz"
fi

CFLAGS="$CFLAGS $LIBCURL_CFLAGS"
CPPFLAGS="$CPPFLAGS $LIBCURL_CPPFLAGS"
LDFLAGS="$LDFLAGS $LIBCURL_LDFLAGS"

# AC_CHECK_LIB([curl], [curl_multi_timeout],
#    have_libcurl=yes,
#    have_libcurl=no AC_MSG_ERROR([curl library required])
# )

# LIBCURL_CHECK_CONFIG([yes], 7.15, curlconfig=yes, curlconfig=no)

AC_SUBST(LIBCURL)
AC_SUBST(LIBCURL_CFLAGS)
AC_SUBST(LIBCURL_CPPFLAGS)
# AC_SUBST(LIBCURL_LDFLAGS)

AC_SUBST(JANSSON_LIBS)
AC_SUBST(PTHREAD_FLAGS)
AC_SUBST(PTHREAD_LIBS)
AC_SUBST(WS2_LIBS)

AC_CONFIG_FILES([
	Makefile
	compat/Makefile
	compat/jansson/Makefile
	])
AC_OUTPUT
