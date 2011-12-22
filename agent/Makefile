TCF_AGENT_DIR=.

include $(TCF_AGENT_DIR)/Makefile.inc

# include custom Makefile fragments if defined

ifdef MAKE_INC
include $(MAKE_INC)
endif

ifdef LUADIR
  EXECS += $(BINDIR)/tcflua$(EXTEXE)
  OPTS += -DPATH_LUA="$(LUADIR)" "-I$(LUADIR)/include"
  LUALIBS = $(LIBS) $(LUADIR)/lib/liblua$(EXTLIB)
  ifeq ($(OPSYS),Msys)
    LUALIBS += -lm
  else
    ifneq ($(OPSYS),Windows)
      LUALIBS += -lm -ldl
    endif
  endif
endif

LIBTCF		?= $(BINDIR)/libtcf$(EXTLIB)

LINK_FLAGS	+= $(LINK_OPTS)

all:	$(EXECS)

libtcf: $(LIBTCF)

CCDEPS = $(HFILES) Makefile Makefile.inc

ifdef OpenSSL
  CCDEPS += $(LIBSSL)

$(LIBSSL): $(OpenSSL)/Makefile
	bin/build-openssl "$(OpenSSL)" "$(OPSYS)" "$(MACHINE)" "$(CONF)"
endif

CCDEPS += $(EXTRA_CCDEPS)

override CFLAGS += $(OPTS)

$(LIBTCF) : $(OFILES)
	$(AR) $(AR_FLAGS) $(AR_OUT_F)$@ $^
	$(RANLIB)

$(BINDIR)/agent$(EXTEXE): $(BINDIR)/tcf/main/main$(EXTOBJ) $(LIBTCF)
	$(LINK) $(LINK_FLAGS) $(LINK_OUT_F)$@ $(BINDIR)/tcf/main/main$(EXTOBJ) \
		$(LIBTCF) $(LIBS)

$(BINDIR)/client$(EXTEXE): $(BINDIR)/tcf/main/main_client$(EXTOBJ) $(LIBTCF)
	$(LINK) $(LINK_FLAGS) $(LINK_OUT_F)$@ \
		$(BINDIR)/tcf/main/main_client$(EXTOBJ) $(LIBTCF) $(LIBS)

ifdef LUADIR
$(BINDIR)/tcflua$(EXTEXE): $(BINDIR)/tcf/main/main_lua$(EXTOBJ) $(LIBTCF)
	$(LINK) $(LINK_FLAGS) $(EXPORT_DYNAMIC) $(LINK_OUT_F)$@ \
		$(BINDIR)/tcf/main/main_lua$(EXTOBJ) $(LIBTCF) $(LUALIBS)
endif

$(BINDIR)/tcfreg$(EXTEXE): $(BINDIR)/tcf/main/main_reg$(EXTOBJ) $(LIBTCF)
	$(LINK) $(LINK_FLAGS) $(LINK_OUT_F)$@ $(BINDIR)/tcf/main/main_reg$(EXTOBJ) \
		$(LIBTCF) $(LIBS)

$(BINDIR)/valueadd$(EXTEXE): $(BINDIR)/tcf/main/main_va$(EXTOBJ) $(LIBTCF)
	$(LINK) $(LINK_FLAGS) $(LINK_OUT_F)$@ $(BINDIR)/tcf/main/main_va$(EXTOBJ) \
		$(LIBTCF) $(LIBS)

$(BINDIR)/tcflog$(EXTEXE): $(BINDIR)/tcf/main/main_log$(EXTOBJ) $(LIBTCF)
	$(LINK) $(LINK_FLAGS) $(LINK_OUT_F)$@ $(BINDIR)/tcf/main/main_log$(EXTOBJ) \
		$(LIBTCF) $(LIBS)

$(BINDIR)/tcf/main/test$(EXTOBJ): tcf/main/test.c $(CCDEPS)
	@$(call MKDIR,$(dir $@))
	$(CC) $(filter-out -O%,$(CFLAGS)) -O0 $(OUT_OBJ_F)$@ $(NO_LINK_F) $<

$(BINDIR)/%$(EXTOBJ): %.c $(CCDEPS)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(OUT_OBJ_F)$@ $(NO_LINK_F) $<

clean::
	$(call RMDIR,$(BINDIR))

ifeq ($(OPSYS),GNU/Linux)

install: all
	install -d -m 755 $(INSTALLROOT)$(SBIN)
	install -d -m 755 $(INSTALLROOT)$(INIT)
	install -d -m 755 $(INSTALLROOT)$(INCLUDE)
	install -d -m 755 $(INSTALLROOT)$(INCLUDE)/tcf
	install -d -m 755 $(INSTALLROOT)$(INCLUDE)/tcf/framework
	install -d -m 755 $(INSTALLROOT)$(INCLUDE)/tcf/services
	install -c $(BINDIR)/agent -m 755 $(INSTALLROOT)$(SBIN)/tcf-agent
	install -c $(BINDIR)/client -m 755 $(INSTALLROOT)$(SBIN)/tcf-client
	install -c tcf/main/tcf-agent.init -m 755 $(INSTALLROOT)$(INIT)/tcf-agent
	install -c tcf/config.h -m 755 $(INSTALLROOT)$(INCLUDE)/tcf/config.h
	install -c -t $(INSTALLROOT)$(INCLUDE)/tcf/framework -m 644 tcf/framework/*.h
	install -c -t $(INSTALLROOT)$(INCLUDE)/tcf/services -m 644 tcf/services/*.h

ALLFILES = Makefile* *.html *.sln *.vcproj *.h bin tcf

tcf-agent-$(VERSION).tar.bz2: $(HFILES) $(CFILES) Makefile Makefile.inc \
			      tcf/main/tcf-agent.spec tcf/main/tcf-agent.init
	rm -rf tcf-agent-$(VERSION) tcf-agent-$(VERSION).tar.bz2
	mkdir tcf-agent-$(VERSION)
	tar c $(ALLFILES) | tar x -C tcf-agent-$(VERSION)
	tar cjf tcf-agent-$(VERSION).tar.bz2 tcf-agent-$(VERSION)
	rm -rf tcf-agent-$(VERSION)

tar: tcf-agent-$(VERSION).tar.bz2

rpm: all tar
	rm -rf RPM
	mkdir RPM RPM/BUILD RPM/RPMS RPM/RPMS/`uname -i` \
	      RPM/RPMS/noarch RPM/SOURCES RPM/SPECS RPM/SRPMS RPM/tmp
	echo "%_topdir $(PWD)/RPM" >~/.rpmmacros
	echo "%_tmppath $(PWD)/RPM/tmp" >>~/.rpmmacros
	rpmbuild -ta tcf-agent-$(VERSION).tar.bz2
	mv RPM/RPMS/`uname -i`/*.rpm .
	mv RPM/SRPMS/*.rpm .
	rm -rf RPM ~/.rpmmacros

clean::
	rm -rf RPM *.tar *.tar.bz2 *.rpm

endif
