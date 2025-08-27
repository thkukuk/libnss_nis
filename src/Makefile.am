#
# Copyright (c) 2015, 2016 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@thkukuk.de>
#
# Process this file with automake to produce Makefile.in.
#

CLEANFILES = *~

EXTRA_DIST = libnss_nis.map files-parse.c

AM_CFLAGS = -D_REENTRANT=1
AM_CPPFLAGS = -I$(srcdir) @TIRPC_CFLAGS@ @LIBNSL_CFLAGS@

lib_LTLIBRARIES = libnss_nis.la

noinst_HEADERS = libc-lock.h libc-symbols.h netgroup.h nss-nis.h \
		 mapv4v6addr.h
check_PROGRAMS = nss_loader-test
nss_loader_test_LDADD = -ldl

TESTS = $(check_PROGRAMS)

# Build the version script from a template, pruning _nss_nis_getsecretkey
# when xdecrypt() was not detected by configure (i.e., HAVE_XDECRYPT is unset).
BUILT_SOURCES = libnss_nis.map
EXTRA_DIST   += libnss_nis.map.in
CLEANFILES   += libnss_nis.map

libnss_nis.map: $(srcdir)/libnss_nis.map.in $(top_builddir)/config.h
	$(AM_V_GEN) { \
	  if grep -q '^[[:space:]]*#define[[:space:]]\+HAVE_XDECRYPT[[:space:]]\+1' $(top_builddir)/config.h ; then \
	    cp $(srcdir)/libnss_nis.map.in $@ ; \
	  else \
	    sed 's/ _nss_nis_getsecretkey;//g' \
	        $(srcdir)/libnss_nis.map.in > $@ ; \
	  fi ; \
	}

libnss_nis_la_LDFLAGS = -version-info 2:0:0 \
	-Wl,--version-script=$(builddir)/libnss_nis.map
libnss_nis_la_LIBADD = @LIBNSL_LIBS@
libnss_nis_la_SOURCES = nis-alias.c nis-ethers.c nis-grp.c nis-hosts.c \
			nis-initgroups.c nis-netgrp.c nis-network.c  \
			nis-proto.c nis-publickey.c nis-pwd.c nis-rpc.c \
			nis-service.c nis-spwd.c nss-nis.c nss-default.c
