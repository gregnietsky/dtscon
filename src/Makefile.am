ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I./include
EXTRA_DIST = include

bin_PROGRAMS = dtscon
dtscon_SOURCES = newt.c dtscon.c nform.c nmenu.c genconf.c
dtscon_CFLAGS = $(AM_CFLAGS) $(DTSAPPLIB_CFLAGS) $(SLANG_CFLAGS) $(NEWT_CFLAGS) $(DEVELOPER_CFLAGS) $(CURL_CFLAGS)
dtscon_LDADD = $(DTSAPPLIB_LIBS) $(SLANG_LIBS) $(NEWT_LIBS) $(CURL_LIBS) $(LIBS)
