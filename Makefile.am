# Manage configure options
AM_CPPFLAGS=-Wall
AM_CFLAGS=-Wall -g -O0
AM_CXXFLAGS=-Wall -g -O0
AM_LDFLAGS=

bin_PROGRAMS = xeert
xeert_SOURCES = \
			   src/xeert.cpp \
			   src/parse_x509.cpp \
			   src/cmd_diff.cpp \
			   src/cmd_grep.cpp \
			   src/cmd_show.cpp

xeert_CPPFLAGS = @OPENSSL_CFLAGS@
xeert_LDADD = @OPENSSL_LIBS@

