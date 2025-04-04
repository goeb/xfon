# Manage configure options
AM_CPPFLAGS = -Wall
AM_CFLAGS = -Wall
AM_CXXFLAGS = -Wall
AM_LDFLAGS =

bin_PROGRAMS = xeert
xeert_SOURCES = \
			src/certificate.cpp \
			src/cmd_diff.cpp \
			src/cmd_grep.cpp \
			src/cmd_show.cpp \
			src/data_model.cpp \
			src/der_decode_x509.cpp \
			src/hierarchy.cpp \
			src/oid_name.cpp \
			src/parse_x509.cpp \
			src/render_text.cpp \
			src/util.cpp \
			src/xeert.cpp

xeert_CPPFLAGS = @OPENSSL_CFLAGS@
xeert_LDADD = @OPENSSL_LIBS@

SUBDIRS = test
