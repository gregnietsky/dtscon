ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I./include

bin_PROGRAMS = dtscon
dtscon_SOURCES = newt.c dtscon.c nform.c nmenu.c genconf.c ip4util.c curl.c util.c
dtscon_CFLAGS = $(FWORK_CFLAGS) $(SLANG_CFLAGS) $(NEWT_CFLAGS) $(DEVELOPER_CFLAGS) $(CURL_CFLAGS)
dtscon_LDADD = $(FWORK_LIBS) $(SLANG_LIBS) $(NEWT_LIBS) $(CURL_LIBS) $(LIBS)
