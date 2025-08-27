#!/bin/sh -x

rm -fv ltmain.sh config.sub config.guess config.h.in aclocal.m4 -r m4
aclocal
autoheader
libtoolize --automake --copy
automake --add-missing --copy --force
autoreconf
chmod 755 configure
