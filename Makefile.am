AUTOMAKE_OPTIONS = no-dependencies foreign

sbin_PROGRAMS = smc-milter

smc_milter_SOURCES = \
smc-milter.c smc-milter.h autospf.c autospf.h utils.c utils.h virus.c virus.h spf.c spf.h

dist_noinst_DATA = \
smc-milter.conf smc-milter.hosts smc-milter.users

DOCLIST = AUTHORS COPYING INSTALL NEWS README
CONFDIR = $(DESTDIR)/$(sysconfdir)
EXTRA_DIST = smc-milter.init-gentoo smc-milter.init-rh smc-milter.init-deb smc-milter.sh

install-data-hook: $(EXTRA_DIST) smc-milter.conf smc-milter.hosts smc-milter.users
	test -z $(CONFDIR) || $(mkdir_p) $(CONFDIR);
	if test -f $(CONFDIR)/smc-milter.conf; then \
	    $(INSTALL_DATA) smc-milter.conf $(CONFDIR)/smc-milter.conf.new; \
	else $(INSTALL_DATA) smc-milter.conf $(CONFDIR); \
	fi
	if test -f $(CONFDIR)/smc-milter.hosts; then \
	    $(INSTALL_DATA) smc-milter.hosts $(CONFDIR)/smc-milter.hosts.new; \
	else $(INSTALL_DATA) smc-milter.hosts $(CONFDIR); \
	fi
	if test -f $(CONFDIR)/smc-milter.users; then \
	    $(INSTALL_DATA) smc-milter.users $(CONFDIR)/smc-milter.users.new; \
	else $(INSTALL_DATA) smc-milter.users $(CONFDIR); \
	fi
