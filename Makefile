CXX ?=g++

INCL=

LIBS=-lgcrypt -lpthread
CXXFLAGS ?= -O2 -g
CXXFLAGS +=-Wall -shared -fPIC -DPIC


PLUGIN=radiusplugin.so

OBJECTS=\
  RadiusClass/RadiusAttribute.o \
  RadiusClass/RadiusPacket.o \
  RadiusClass/RadiusConfig.o \
  RadiusClass/RadiusServer.o \
  RadiusClass/RadiusVendorSpecificAttribute.o \
  AccountingProcess.o \
  Exception.o \
  PluginContext.o \
  UserAuth.o \
  AcctScheduler.o \
  IpcSocket.o \
  radiusplugin.o \
  User.o \
  AuthenticationProcess.o \
  main.o \
  UserAcct.o \
  UserPlugin.o \
  Config.o

ifeq ($(V),1)
Q=
NQ=true
else
Q=@
NQ=echo
endif

all: $(PLUGIN)

$(PLUGIN): $(OBJECTS)
	@$(NQ) 'CXXLD $@'
	$(Q)$(CXX) $(CXXFLAGS) $(OBJECTS) -o $(PLUGIN) $(LDFLAGS) $(LIBS)

%.o: %.cpp
	@$(NQ) 'CXX $@'
	$(Q)$(CXX) $(INCL) $(CXXFLAGS) -o $@ -c $<

test: $(OBJECTS)
	@$(NQ) 'CXX $@'
	$(Q)$(CXX) -Wall $(OBJECTS) -o main $(LDFLAGS) $(LIBS)

clean:
	rm -f $(PLUGIN) *.o */*.o

# use make dist-gz PLUGIN_VERS=2.2
dist-gz:
	@[ x"$(PLUGIN_VERS)" != x"" ] || ( echo 'Need a non empty PLUGIN_VERS value to create versionned tar' && false )
	rm -rf ./tmp && mkdir tmp
	cd tmp && cvs -z3 -d `cat ../CVS/Root` export -DNOW radiusplugin
	mv tmp/radiusplugin tmp/radiusplugin-$(PLUGIN_VERS)
	rm -rf tmp/radiusplugin-$(PLUGIN_VERS)/radiusplugin_v2.0a
	cd tmp && tar zcf ../radiusplugin-$(PLUGIN_VERS).tar.gz radiusplugin-$(PLUGIN_VERS)
	@rm -rf ./tm