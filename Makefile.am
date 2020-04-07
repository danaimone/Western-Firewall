
sbin_PROGRAMS=wfw
dist_sysconf_DATA=src/wfw.cfg

CFLAGS=-Wall

EXTRA_DIST=				\
	src/hash.h			\
	src/conf.h			\
	tests/test_config	

TESTS=$(check_PROGRAMS)

AM_CPPFLAGS=-I$(top_srcdir)/src

wfw_CFLAGS=     \
    -DSYSCONFDIR="$(sysconfdir)"
wfw_SOURCES=	\
	src/wfw.c	\
	src/hash.c	\
	src/conf.c


check_PROGRAMS=ht_test cfg_test

ht_test_CFLAGS=@CHECK_CFLAGS@
ht_test_LDADD=@CHECK_LIBS@
ht_test_SOURCES=     \
	tests/ht_test.c  \
	src/hash.c

cfg_test_CFLAGS=\
	@CHECK_CFLAGS@ \
	-DTESTSDIR="$(srcdir)/tests"
cfg_test_LDADD=@CHECK_LIBS@
cfg_test_SOURCES=     \
	tests/cfg_test.c  \
	src/conf.c        \
	src/hash.c

