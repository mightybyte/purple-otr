AM_CFLAGS=	@LIBGCRYPT_CFLAGS@ @LIBOTR3_CFLAGS@ @EXTRA_CFLAGS@
AM_CFLAGS+=	-DPURPLE_PLUGINS \
		-DPIDGIN_OTR_VERSION=\"@VERSION@\" \
		-DLOCALEDIR=\"$(datadir)/locale\"

SUBDIRS=	po

plugindir=		${libdir}/purple-2

plugin_LTLIBRARIES=	purple-otr.la

purple_otr_la_SOURCES=	otr-plugin.c ui.c dialogs.c purple-ui.c purple-dialog.c
purple_otr_la_LDFLAGS=	-module -avoid-version
purple_otr_la_LDFLAGS+=	@LIBGCRYPT_LIBS@ @LIBOTR3_LIBS@

EXTRA_DIST=		dialogs.h gtk-dialog.h gtk-ui.h otr-plugin.h ui.h \
			otr-icons.h tooltipmenu.h purple-dialog.h purple-ui.h \
			Makefile.mingw packaging/windows/pidgin-otr.nsi \
			packaging/fedora/pidgin-otr.spec po/Makefile.mingw \
			po/README intltool-extract.in intltool-merge.in \
			intltool-update.in Makefile.static

DISTCLEANFILES=		intltool-extract intltool-merge intltool-update
