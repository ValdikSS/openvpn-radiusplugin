BLUE    =\033[20;36m
GREEN   =\033[32m
RED     =\033[31m
ESC     =\033[0m
OK      =[$(GREEN) Ok $(ESC)]
FAILED  =[$(RED) failed $(ESC)]

CC=g++
INCL=
LDFLAGS=
LIBS=-lgcrypt
CFLAGS=-Wall -shared
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

all: $(PLUGIN)

$(PLUGIN): $(OBJECTS)
	@echo -e 'BIN: $(GREEN) $(PLUGIN) $(ESC)'
	@$(CC) $(CFLAGS) $(OBJECTS) -o $(PLUGIN) $(LDFLAGS) $(LIBS)

%.o: %.cpp
	@echo -e 'OBJ: $(GREEN) $@ $(ESC)'
	@$(CC) $(INCL) $(CFLAGS) -o $@ -c $<

clean:
	-rm $(PLUGIN) *.o
