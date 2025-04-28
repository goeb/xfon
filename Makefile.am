# Manage configure options
AM_CPPFLAGS = -Wall
AM_CFLAGS = -Wall
AM_CXXFLAGS = -Wall
AM_LDFLAGS =

bin_PROGRAMS = xfon
xfon_SOURCES = \
			src/certificate.cpp \
			src/cmd_diff.cpp \
			src/cmd_grep.cpp \
			src/cmd_show.cpp \
			src/der_decode_x509.cpp \
			src/hierarchy.cpp \
			src/journal.cpp \
			src/oid_name.cpp \
			src/render_text.cpp \
			src/util.cpp \
			src/x509_verify.cpp \
			src/xfon.cpp

xfon_CPPFLAGS = @OPENSSL_CFLAGS@
xfon_LDADD = @OPENSSL_LIBS@

SUBDIRS = test
