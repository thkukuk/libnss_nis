#
# Copyright (c) 2015 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@thkukuk.de>
#
# Process this file with automake to produce Makefile.in.
#

CLEANFILES = *~

EXTRA_DIST = libnss_nis.map files-parse.c databases.def

AM_CFLAGS = -D_REENTRANT=1
AM_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/lib @LIBNSL_CFLAGS@

lib_LTLIBRARIES = libnss_nis.la

noinst_HEADERS = libc-lock.h libc-symbols.h netgroup.h nss-nis.h nsswitch.h
noinst_PROGRAMS = nss_loader-test
nss_loader_test_LDADD = -ldl

libnss_nis_la_LDFLAGS = -version-info 2:0:0 \
	-Wl,--version-script=$(srcdir)/libnss_nis.map
libnss_nis_la_LIBADD = @LIBNSL_LIBS@
libnss_nis_la_SOURCES = nis-alias.c nis-ethers.c nis-grp.c nis-hosts.c \
			nis-initgroups.c nis-netgrp.c nis-network.c  \
			nis-proto.c nis-publickey.c nis-pwd.c nis-rpc.c \
			nis-service.c nis-spwd.c nss-nis.c nss-default.c

